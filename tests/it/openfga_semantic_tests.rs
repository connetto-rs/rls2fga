#![cfg(not(target_os = "windows"))]

use openfga_client::client::{OpenFgaClient, TupleKey};
use openfga_client::tonic::transport::Channel;

use rls2fga::types::{records_from_row, ConfidenceLevel};

use crate::support;

struct Scenario {
    name: &'static str,
    fixture: &'static str,
    min_confidence: ConfidenceLevel,
    tuples: Vec<(&'static str, &'static str, &'static str)>,
    rows: Vec<(&'static str, support::Row)>,
    checks: Vec<(&'static str, &'static str, &'static str, bool)>,
}

#[tokio::test]
#[ignore = "requires Docker and OpenFGA container"]
async fn openfga_semantic_checks_all_patterns() {
    // ── Start shared OpenFGA container ──────────────────────────────────────
    let container = support::containers::start_openfga().await;

    let grpc_port = container.get_host_port_ipv4(8081).await.unwrap();

    // Define scenarios.
    let scenarios = vec![
        // P1: EMI role threshold
        Scenario {
            name: "P1_emi_role_threshold",
            fixture: "earth_metabolome",
            min_confidence: ConfidenceLevel::B,
            tuples: support::openfga::EARTH_METABOLOME_TUPLES.to_vec(),
            rows: vec![],
            checks: support::openfga::EARTH_METABOLOME_CHECKS.to_vec(),
        },
        // P2: Role IN-list
        Scenario {
            name: "P2_role_in_list",
            fixture: "role_in_list",
            min_confidence: ConfidenceLevel::B,
            tuples: vec![
                ("ownables:res1", "owner_id", "owner_grants_owner:o1"),
                ("owner_grants_owner:o1", "owner_user", "user:alice"),
                (
                    "owner_grants_owner:o1",
                    "owner_team",
                    "team_members_team:alpha",
                ),
                ("team_members_team:alpha", "member", "user:bob"),
                ("owner_grants_owner:o1", "grant_viewer", "user:carol"),
                ("owner_grants_owner:o1", "grant_editor", "user:dave"),
            ],
            rows: vec![],
            checks: vec![
                ("user:alice", "can_select", "ownables:res1", true),
                ("user:bob", "can_select", "ownables:res1", true),
                ("user:carol", "can_select", "ownables:res1", true),
                ("user:dave", "can_select", "ownables:res1", true),
                ("user:nobody", "can_select", "ownables:res1", false),
                // `role_editor` and `role_admin` used to be checked here. The inliner
                // folds the hierarchy into `can_select`, so no permission names those
                // rungs and they are no longer declared. What they proved, that the
                // hierarchy composes in the right order, is pinned by the
                // `generate_role_in_list_model` snapshot instead.
            ],
        },
        // P3: Direct ownership
        Scenario {
            name: "P3_simple_ownership",
            fixture: "simple_ownership",
            min_confidence: ConfidenceLevel::B,
            tuples: vec![
                ("resources:r1", "owner", "user:alice"),
                ("resources:r2", "owner", "user:bob"),
            ],
            rows: vec![],
            checks: vec![
                ("user:alice", "can_select", "resources:r1", true),
                ("user:alice", "can_delete", "resources:r1", true),
                ("user:bob", "can_select", "resources:r1", false),
                ("user:bob", "can_delete", "resources:r1", false),
                ("user:bob", "can_select", "resources:r2", true),
                ("user:alice", "can_select", "resources:r2", false),
                ("user:nobody", "can_select", "resources:r1", false),
            ],
        },
        // P4: EXISTS membership (tuple-to-userset)
        Scenario {
            name: "P4_membership_check",
            fixture: "membership_check",
            min_confidence: ConfidenceLevel::B,
            tuples: vec![],
            rows: vec![
                (
                    "team_members",
                    support::row(&[("team_id", "t1"), ("user_id", "alice")]),
                ),
                (
                    "team_members",
                    support::row(&[("team_id", "t1"), ("user_id", "bob")]),
                ),
                (
                    "team_members",
                    support::row(&[("team_id", "t2"), ("user_id", "carol")]),
                ),
                ("projects", support::row(&[("id", "p1"), ("team_id", "t1")])),
                ("projects", support::row(&[("id", "p2"), ("team_id", "t2")])),
            ],
            checks: vec![
                ("user:alice", "can_select", "projects:p1", true),
                ("user:bob", "can_select", "projects:p1", true),
                ("user:carol", "can_select", "projects:p2", true),
                ("user:carol", "can_select", "projects:p1", false),
                ("user:alice", "can_select", "projects:p2", false),
                ("user:nobody", "can_select", "projects:p1", false),
            ],
        },
        // P5: Parent inheritance (nested tuple-to-userset)
        Scenario {
            name: "P5_parent_inheritance",
            fixture: "parent_inheritance",
            min_confidence: ConfidenceLevel::B,
            tuples: vec![
                ("projects:proj1", "owner", "user:alice"),
                ("projects:proj2", "owner", "user:bob"),
                ("tasks:task1", "projects", "projects:proj1"),
                ("tasks:task2", "projects", "projects:proj1"),
                ("tasks:task3", "projects", "projects:proj2"),
            ],
            rows: vec![],
            checks: vec![
                ("user:alice", "can_select", "tasks:task1", true),
                ("user:alice", "can_select", "tasks:task2", true),
                ("user:alice", "can_select", "projects:proj1", true),
                ("user:alice", "can_select", "tasks:task3", false),
                ("user:bob", "can_select", "tasks:task3", true),
                ("user:bob", "can_select", "tasks:task1", false),
                ("user:nobody", "can_select", "tasks:task1", false),
            ],
        },
        // P6: Boolean flag (wildcard)
        Scenario {
            name: "P6_public_flag",
            fixture: "public_flag",
            min_confidence: ConfidenceLevel::B,
            tuples: vec![("articles:a1", "public_when_is_public", "user:*")],
            rows: vec![],
            checks: vec![
                ("user:anyone", "can_select", "articles:a1", true),
                ("user:alice", "can_select", "articles:a1", true),
                ("user:anyone", "can_select", "articles:a2", false),
                ("user:alice", "can_select", "articles:a2", false),
            ],
        },
        // P7: ABAC AND (relationship plus attribute guard)
        Scenario {
            name: "P7_abac_status",
            fixture: "abac_status",
            min_confidence: ConfidenceLevel::C,
            tuples: vec![
                ("ownables:item1", "owner_id", "owner_grants_owner:o1"),
                // item1 is a status = 'active' row: the guard now translates as a
                // per-row gate the tuple loader fills, rather than being dropped
                // with a runtime-enforcement note.
                ("ownables:item1", "public_where_status_75289b56", "user:*"),
                // item2 is not active, so the guard denies whatever the ladder says.
                ("ownables:item2", "owner_id", "owner_grants_owner:o1"),
                ("owner_grants_owner:o1", "owner_user", "user:alice"),
                (
                    "owner_grants_owner:o1",
                    "owner_team",
                    "team_members_team:alpha",
                ),
                ("team_members_team:alpha", "member", "user:bob"),
                ("owner_grants_owner:o1", "grant_editor", "user:carol"),
                // Dave's viewer grant used to be written here. The policy needs the
                // editor rung, so `grant_viewer` reaches no permission and is no longer
                // declared. He stays the denied case with no grant at all.
            ],
            rows: vec![],
            checks: vec![
                // `abac_status` declares only an UPDATE policy, so no SELECT policy
                // admits any row and `can_update` denies: naming a row to change means
                // reading it. The statement this scenario means is a blanket update,
                // which reads nothing, and that is what the second relation answers.
                ("user:alice", "can_update", "ownables:item1", false),
                ("user:bob", "can_update", "ownables:item1", false),
                ("user:carol", "can_update", "ownables:item1", false),
                (
                    "user:alice",
                    "can_update_without_reading",
                    "ownables:item1",
                    true,
                ),
                (
                    "user:bob",
                    "can_update_without_reading",
                    "ownables:item1",
                    true,
                ),
                (
                    "user:carol",
                    "can_update_without_reading",
                    "ownables:item1",
                    true,
                ),
                (
                    "user:dave",
                    "can_update_without_reading",
                    "ownables:item1",
                    false,
                ),
                (
                    "user:nobody",
                    "can_update_without_reading",
                    "ownables:item1",
                    false,
                ),
                (
                    "user:alice",
                    "can_update_without_reading",
                    "ownables:item2",
                    false,
                ),
            ],
        },
        // P8: Compound OR (P3 owner plus P6 public)
        Scenario {
            name: "P8_compound_or",
            fixture: "compound_or",
            min_confidence: ConfidenceLevel::B,
            tuples: vec![
                ("documents:doc1", "owner", "user:alice"),
                ("documents:doc1", "public_when_is_public", "user:*"),
                ("documents:doc2", "owner", "user:bob"),
            ],
            rows: vec![],
            checks: vec![
                ("user:alice", "can_select", "documents:doc1", true),
                ("user:bob", "can_select", "documents:doc2", true),
                ("user:bob", "can_select", "documents:doc1", true),
                ("user:anyone", "can_select", "documents:doc1", true),
                ("user:alice", "can_select", "documents:doc2", false),
                ("user:anyone", "can_select", "documents:doc2", false),
                ("user:nobody", "can_select", "documents:doc2", false),
            ],
        },
        // P10: Constant bool intersection (permissive TRUE and restrictive FALSE)
        Scenario {
            name: "P10_constant_bool",
            fixture: "constant_bool",
            min_confidence: ConfidenceLevel::B,
            tuples: vec![("docs:d1", "public_viewer", "user:*")],
            rows: vec![],
            checks: vec![
                ("user:anyone", "can_select", "docs:d1", false),
                ("user:alice", "can_select", "docs:d1", false),
            ],
        },
        // P2: pg_has_role gate. The role membership is written by hand, since it lives
        // outside the policy tables and no generated query can produce it. The scope tuple
        // is what the generated SQL emits, one per row.
        //
        // The scope is named after what it is, membership of editor, so a change to that
        // rule renames the relation and the server refuses these writes rather than
        // answering with a stale object. `role_scope_name("member", ["editor"])` is the
        // rule, and `generator_tests` derives it rather than spelling it.
        Scenario {
            name: "P2_pg_role_gate",
            fixture: "pg_role_gate",
            min_confidence: ConfidenceLevel::B,
            tuples: vec![
                (
                    "docs:d1",
                    "scope_member_editor_89c73e0a",
                    "pg_role_scope:scope_member_editor_89c73e0a",
                ),
                (
                    "pg_role_scope:scope_member_editor_89c73e0a",
                    "roles",
                    "pg_role:editor",
                ),
                ("pg_role:editor", "member", "user:alice"),
            ],
            rows: vec![],
            checks: vec![
                // RLS admits every member of 'editor', so the model has to as well.
                ("user:alice", "can_select", "docs:d1", true),
                // And nobody else, which is what makes the grant a gate.
                ("user:bob", "can_select", "docs:d1", false),
            ],
        },
    ];

    // ── Run all scenarios ───────────────────────────────────────────────────
    let mut all_failures = Vec::new();

    for scenario in &scenarios {
        let scenario_failures = run_scenario(grpc_port, scenario).await;
        if !scenario_failures.is_empty() {
            all_failures.push(format!(
                "[{}] {} failure(s):\n{}",
                scenario.name,
                scenario_failures.len(),
                scenario_failures.join("\n")
            ));
        }
    }

    assert!(
        all_failures.is_empty(),
        "Authorization check failures across scenarios:\n\n{}",
        all_failures.join("\n\n")
    );
}

async fn run_scenario(grpc_port: u16, scenario: &Scenario) -> Vec<String> {
    // 1. Fresh client for each scenario (create_store needs &mut)
    let mut service_client = support::openfga::connect(grpc_port).await;

    // 2. Create store
    let store_id = support::openfga::create_store(&mut service_client, scenario.name).await;

    // 3. Generate and upload JSON model
    let (classified, db, registry) = support::try_load_fixture_classified(scenario.fixture);
    let outputs = support::plan_at(classified, &db, &registry, scenario.min_confidence);
    let model = outputs.json_model();
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    // 4. Create scoped client
    let client: OpenFgaClient<Channel> = service_client.into_client(&store_id, &model_id);

    // 5. Write tuples
    let mut tuples: Vec<TupleKey> = scenario
        .tuples
        .iter()
        .map(|(obj, rel, user)| support::openfga::make_tuple(obj, rel, user))
        .collect();
    for (table, row) in &scenario.rows {
        for description in outputs
            .tuple_queries()
            .iter()
            .filter_map(|query| query.description.as_ref())
            .filter(|description| {
                description
                    .row_table()
                    .is_some_and(|source| source.name() == *table)
            })
        {
            for record in records_from_row(description, row).expect("the row should yield records")
            {
                tuples.push(support::openfga::make_tuple(
                    &record.object,
                    record.relation.as_str(),
                    &record.subject,
                ));
            }
        }
    }

    support::openfga::write_tuples(&client, tuples).await;

    // 6. Run checks and collect failures
    let mut failures = Vec::new();
    for (user, relation, object, expected) in &scenario.checks {
        let allowed = support::openfga::check_allowed(&client, user, relation, object).await;
        if allowed != *expected {
            failures.push(format!(
                "  {user} {relation} {object}: expected {expected}, got {allowed}"
            ));
        }
    }

    failures
}
