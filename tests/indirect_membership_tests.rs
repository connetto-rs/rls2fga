use rls2fga::classifier::function_registry::{SessionAttribute, SessionAttributeKind};
use rls2fga::parser::sql_parser::parse_schema;
use rls2fga::translator::{Outputs, TranslatorBuilder};
use rls2fga::types::{
    records_from_row, ConfidenceLevel, Record, RecordDerivation, ReplayScope, TranslationNote,
};

mod support;

use support::{INDIRECT_MEMBERSHIP_NESTED_ROLE as NESTED, INDIRECT_MEMBERSHIP_SCHEMA as SCHEMA};

#[cfg(all(not(target_os = "windows"), feature = "client"))]
const ATTRIBUTES: &str = r#"[{"key":"app.user_id","kind":"caller_id"}]"#;

const JOINED: &str = "EXISTS (
    SELECT 1 FROM ownable_ancestors a JOIN memberships m ON m.owner_id = a.owner
    WHERE a.ownable = orders.id AND m.member_id = current_setting('app.user_id', true)
    AND m.role = 'read')";

#[cfg(all(not(target_os = "windows"), feature = "client"))]
const NESTED_IN: &str = "orders.id IN (
    SELECT a.ownable FROM ownable_ancestors a WHERE a.owner IN (
        SELECT m.owner_id FROM memberships m
        WHERE m.member_id = current_setting('app.user_id', true) AND m.role = 'read'))";

fn outputs(schema: &str, policies: &str) -> Outputs {
    let db = parse_schema(&format!("{schema} {policies}")).unwrap();
    TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_session_attributes([SessionAttribute::setting(
            "app.user_id",
            SessionAttributeKind::CallerId,
        )])
        .build()
        .translate(&db)
        .unwrap()
        .outputs_accepting_gaps()
}

fn row_records(outputs: &Outputs, table_name: &str, row: &serde_json::Value) -> Vec<Record> {
    outputs
        .tuple_queries()
        .iter()
        .filter_map(|query| query.description.as_ref())
        .filter(|description| {
            matches!(&description.derivation,
                RecordDerivation::FromRow { table, .. } if table.name() == table_name)
        })
        .flat_map(|description| {
            records_from_row(description, &support::JsonRowValues(row)).unwrap()
        })
        .collect()
}

#[test]
fn both_spellings_report_row_local_sources_and_nonlocal_permission() {
    for predicate in [NESTED, JOINED] {
        let outputs = outputs(
            SCHEMA,
            &format!("CREATE POLICY orders_read ON orders FOR SELECT USING ({predicate});"),
        );
        assert!(
            matches!(
                outputs.confidence_summary(),
                [(_, ConfidenceLevel::A | ConfidenceLevel::B)]
            ),
            "{}",
            outputs.report()
        );
        let closure = row_records(
            &outputs,
            "ownable_ancestors",
            &serde_json::json!({"ownable":"o1","owner":"ancestor"}),
        );
        assert_eq!(closure.len(), 1, "{}", outputs.report());
        assert_eq!(closure[0].object, "orders:o1");
        assert_eq!(closure[0].subject, "owners:ancestor");
        let members = row_records(
            &outputs,
            "memberships",
            &serde_json::json!({"owner_id":"ancestor","member_id":"reader","role":"read"}),
        );
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].object, "owners:ancestor");
        assert_eq!(members[0].subject, "user:reader");
        assert_eq!(
            row_records(
                &outputs,
                "memberships",
                &serde_json::json!({"owner_id":"ancestor","member_id":"reader","role":"write"}),
            ),
            []
        );
        assert_eq!(
            row_records(
                &outputs,
                "ownable_ancestors",
                &serde_json::json!({"ownable":"o1","owner":null}),
            ),
            []
        );
        let relations = outputs.translation().relations();
        let permission = relations
            .iter()
            .find(|relation| {
                relation.type_name.as_str() == "orders"
                    && relation.relation.as_str() == "can_select"
            })
            .unwrap();
        assert!(!permission.from_one_row);
        assert!(permission.decision.is_none());
        assert!(!permission.grants_nobody);
        for record in closure.iter().chain(&members) {
            let relation = relations
                .iter()
                .find(|relation| {
                    record
                        .object
                        .starts_with(&format!("{}:", relation.type_name))
                        && relation.relation.as_str() == record.relation
                })
                .unwrap();
            assert!(!relation.from_one_row);
            assert!(relation.decision.is_none());
        }
    }
}

#[test]
fn every_listed_role_has_a_distinct_membership_relation() {
    let predicate = NESTED.replace("m.role = 'read'", "m.role IN ('read', 'write', 'admin')");
    let outputs = outputs(
        SCHEMA,
        &format!("CREATE POLICY orders_read ON orders FOR SELECT USING ({predicate});"),
    );
    let roles: Vec<_> = ["read", "write", "admin"]
        .iter()
        .map(|role| {
            let records = row_records(
                &outputs,
                "memberships",
                &serde_json::json!({
                    "owner_id":"ancestor", "member_id":"reader", "role":role
                }),
            );
            assert_eq!(records.len(), 1, "{}", outputs.report());
            records[0].relation.clone()
        })
        .collect();
    assert_ne!(roles[0], roles[1]);
    assert_ne!(roles[1], roles[2]);
    assert_ne!(roles[0], roles[2]);
    assert_eq!(
        row_records(
            &outputs,
            "memberships",
            &serde_json::json!({
                "owner_id":"ancestor", "member_id":"reader", "role":"none"
            })
        ),
        []
    );
}

#[test]
fn a_guarded_hop_is_disclosed_and_never_grants() {
    for table in ["ownable_ancestors", "memberships"] {
        let outputs = outputs(
            SCHEMA,
            &format!(
                "ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
             CREATE POLICY scoped ON {table} FOR SELECT USING (current_user = 'restricted');
             CREATE POLICY orders_read ON orders FOR SELECT USING ({NESTED});"
            ),
        );
        assert!(
            outputs.notes().iter().any(|note| matches!(
                note, TranslationNote::MembershipTableGuarded { join_table, .. }
                    if join_table.name() == table
            )),
            "{}",
            outputs.report()
        );
        assert!(
            outputs.translation().relations().iter().any(|relation| {
                relation.type_name.as_str() == "orders"
                    && relation.relation.as_str() == "can_select"
                    && relation.grants_nobody
            }),
            "{}",
            outputs.model()
        );
    }
}

#[cfg(all(not(target_os = "windows"), feature = "client"))]
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn indirect_membership_live_parity() {
    use rls2fga::types::ActionStatement;
    use support::parity::{assert_agrees, assert_postgres, Cluster, ParityCase, Principal};

    let cluster = Cluster::start().await;
    for (spelling, predicate) in [("nested", NESTED), ("joined", JOINED), ("in", NESTED_IN)] {
        for (label, roles, writer_allowed) in [
            ("all", None, true),
            ("read", Some("m.role = 'read'"), false),
            ("list", Some("m.role IN ('read', 'write', 'admin')"), true),
        ] {
            for from_rows in [false, true] {
                let predicate = roles.map_or_else(
                    || predicate.replace("AND m.role = 'read'", ""),
                    |roles| predicate.replace("m.role = 'read'", roles),
                );
                let mut case = ParityCase::reading(
                    &format!("indirect-{spelling}-{label}-{from_rows}"),
                    &format!("{SCHEMA}
                        CREATE POLICY orders_read ON orders FOR SELECT USING ({predicate});"),
                    &[
                        "INSERT INTO principals VALUES ('reader'), ('writer'), ('outsider');
                         INSERT INTO owners VALUES ('ancestor'), ('other');
                         INSERT INTO ownables VALUES ('o1','ancestor'), ('o2','other'), ('o3','ancestor');
                         INSERT INTO orders VALUES ('o1','first'), ('o2','second'), ('o3','unlinked');
                         INSERT INTO ownable_ancestors VALUES ('o1','ancestor'), ('o1','other'), ('o2','other');
                         INSERT INTO memberships VALUES ('ancestor','reader','read'), ('ancestor','writer','write');
                         CREATE ROLE app_reader LOGIN;
                         GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_reader;",
                    ],
                    ["reader", "writer", "outsider"].iter().map(|subject| {
                        Principal::with_setting(subject, "app_reader", "app.user_id", subject)
                    }).collect(),
                ).with_attributes(ATTRIBUTES);
                case.loading_from_rows = from_rows;
                let run = support::parity::run_before(
                    &cluster,
                    &case,
                    core::time::Duration::from_secs(300),
                )
                .await;
                assert_postgres(
                    &case,
                    &run,
                    "reader",
                    "orders:o1",
                    ActionStatement::Select,
                    true,
                );
                assert_postgres(
                    &case,
                    &run,
                    "writer",
                    "orders:o1",
                    ActionStatement::Select,
                    writer_allowed,
                );
                assert_postgres(
                    &case,
                    &run,
                    "reader",
                    "orders:o3",
                    ActionStatement::Select,
                    false,
                );
                assert_agrees(&case, &run);
            }
        }
    }
}

#[cfg(all(not(target_os = "windows"), feature = "client"))]
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn indirect_and_direct_membership_sources_stay_separate_in_both_policy_orders() {
    use rls2fga::types::ActionStatement;
    use support::parity::{assert_agrees, assert_postgres, Cluster, ParityCase, Principal};

    let cluster = Cluster::start().await;
    for owner_name in ["owners".to_string(), "o".repeat(49)] {
        for (read, delete) in [("a_read", "z_delete"), ("z_read", "a_delete")] {
            for from_rows in [false, true] {
                let schema = format!(
                    "{SCHEMA}
                    ALTER TABLE orders ADD COLUMN owner_id TEXT REFERENCES owners(id);
                    CREATE TABLE direct_memberships (
                        owner_id TEXT REFERENCES owners(id),
                        member_id TEXT REFERENCES principals(id),
                        PRIMARY KEY (owner_id, member_id));
                    CREATE POLICY {read} ON orders FOR SELECT USING ({NESTED});
                    CREATE POLICY {delete} ON orders FOR DELETE USING (
                        EXISTS (SELECT 1 FROM direct_memberships d
                            WHERE d.owner_id = orders.owner_id
                            AND d.member_id = current_setting('app.user_id', true)));"
                )
                .replace("owners", &owner_name);
                let seed = "INSERT INTO principals VALUES ('reader'), ('direct'), ('both');
                    INSERT INTO owners VALUES ('ancestor'), ('direct-owner');
                    INSERT INTO ownables VALUES ('o1','ancestor');
                    INSERT INTO orders VALUES ('o1','first','direct-owner');
                    INSERT INTO ownable_ancestors VALUES ('o1','ancestor');
                    INSERT INTO memberships VALUES ('ancestor','reader','read'), ('ancestor','both','read');
                    INSERT INTO direct_memberships VALUES ('direct-owner','direct'), ('direct-owner','both');
                    CREATE ROLE app_reader LOGIN;
                    GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_reader;
                    GRANT DELETE ON orders TO app_reader;".replace("owners", &owner_name);
                let mut case = ParityCase::reading(
                    &format!("source-isolation-{owner_name}-{read}-{from_rows}"),
                    &schema,
                    &[&seed],
                    ["reader", "direct", "both"]
                        .iter()
                        .map(|subject| {
                            Principal::with_setting(subject, "app_reader", "app.user_id", subject)
                        })
                        .collect(),
                )
                .with_attributes(ATTRIBUTES);
                case.loading_from_rows = from_rows;
                let run = support::parity::run_before(
                    &cluster,
                    &case,
                    core::time::Duration::from_secs(300),
                )
                .await;
                for (subject, select, delete) in [
                    ("reader", true, false),
                    ("direct", false, false),
                    ("both", true, true),
                ] {
                    assert_postgres(
                        &case,
                        &run,
                        subject,
                        "orders:o1",
                        ActionStatement::Select,
                        select,
                    );
                    assert_postgres(
                        &case,
                        &run,
                        subject,
                        "orders:o1",
                        ActionStatement::Delete,
                        delete,
                    );
                }
                assert_agrees(&case, &run);
            }
        }
    }
}

#[cfg(all(not(target_os = "windows"), feature = "client"))]
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn indirect_memberships_keep_independent_clock_conditions() {
    use rls2fga::types::ActionStatement;
    use support::parity::{assert_agrees, assert_postgres, Cluster, ParityCase, Principal};

    let cluster = Cluster::start().await;
    let schema = format!(
        "{SCHEMA}
        ALTER TABLE memberships ADD COLUMN expires_at TIMESTAMPTZ;
        ALTER TABLE memberships ADD COLUMN starts_at TIMESTAMPTZ;
        CREATE POLICY a_read ON orders FOR SELECT USING ({});
        CREATE POLICY z_delete ON orders FOR DELETE USING ({});",
        NESTED.replace("m.role = 'read'", "m.expires_at > now()"),
        NESTED.replace("m.role = 'read'", "m.starts_at < now()"),
    );
    for from_rows in [false, true] {
        let mut case = ParityCase::reading(
            &format!("indirect-clock-{from_rows}"),
            &schema,
            &[
                "INSERT INTO principals VALUES ('reader'), ('blocked'), ('both');
                 INSERT INTO owners VALUES ('ancestor');
                 INSERT INTO ownables VALUES ('o1','ancestor');
                 INSERT INTO orders VALUES ('o1','first');
                 INSERT INTO ownable_ancestors VALUES ('o1','ancestor');
                 INSERT INTO memberships VALUES
                    ('ancestor','reader','read',now() + interval '2 years',now() + interval '2 years'),
                    ('ancestor','blocked','read',now() - interval '2 years',now() - interval '2 years'),
                    ('ancestor','both','read',now() + interval '2 years',now() - interval '2 years');
                 CREATE ROLE app_reader LOGIN;
                 GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_reader;
                 GRANT DELETE ON orders TO app_reader;",
            ],
            ["reader", "blocked", "both"].iter().map(|subject| {
                Principal::with_setting(subject, "app_reader", "app.user_id", subject).with_clock()
            }).collect(),
        ).with_attributes(ATTRIBUTES);
        case.loading_from_rows = from_rows;
        let run =
            support::parity::run_before(&cluster, &case, core::time::Duration::from_secs(300))
                .await;
        for (subject, select, delete) in [
            ("reader", true, false),
            ("blocked", false, false),
            ("both", true, true),
        ] {
            assert_postgres(
                &case,
                &run,
                subject,
                "orders:o1",
                ActionStatement::Select,
                select,
            );
            assert_postgres(
                &case,
                &run,
                subject,
                "orders:o1",
                ActionStatement::Delete,
                delete,
            );
        }
        assert_agrees(&case, &run);
    }
}

#[cfg(all(not(target_os = "windows"), feature = "client"))]
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn indirect_membership_witnesses_never_mix_rows() {
    use rls2fga::types::ActionStatement;
    use support::parity::{assert_agrees, assert_postgres, Cluster, ParityCase, Principal};

    let cluster = Cluster::start().await;
    let schema = SCHEMA.replace(
        "PRIMARY KEY (owner_id, member_id)",
        "id INT PRIMARY KEY, trial_ends TIMESTAMPTZ, support_ends TIMESTAMPTZ",
    );
    let predicate = NESTED.replace(
        "m.role = 'read'",
        "m.trial_ends > now() AND m.support_ends > now()",
    );
    for from_rows in [false, true] {
        let mut case = ParityCase::reading(
            &format!("indirect-witness-{from_rows}"),
            &format!("{schema}
                CREATE POLICY orders_read ON orders FOR SELECT USING ({predicate});"),
            &[
                "INSERT INTO principals VALUES ('mixed'), ('reader');
                 INSERT INTO owners VALUES ('ancestor');
                 INSERT INTO ownables VALUES ('o1','ancestor');
                 INSERT INTO orders VALUES ('o1','first');
                 INSERT INTO ownable_ancestors VALUES ('o1','ancestor');
                 INSERT INTO memberships VALUES
                    ('ancestor','mixed','read',1,now() + interval '2 years',now() - interval '2 years'),
                    ('ancestor','mixed','read',2,now() - interval '2 years',now() + interval '2 years'),
                    ('ancestor','reader','read',3,now() + interval '2 years',now() + interval '2 years');
                 CREATE ROLE app_reader LOGIN;
                 GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_reader;",
            ],
            ["mixed", "reader"].iter().map(|subject| {
                Principal::with_setting(subject, "app_reader", "app.user_id", subject).with_clock()
            }).collect(),
        ).with_attributes(ATTRIBUTES).also_at(
            "3 years",
            "SELECT m.member_id AS subject, 'orders:' || o.id AS object
             FROM orders o JOIN ownable_ancestors a ON a.ownable = o.id
             JOIN memberships m ON m.owner_id = a.owner
             WHERE m.trial_ends > $1::timestamptz AND m.support_ends > $1::timestamptz
             UNION ALL
             SELECT p.id AS subject, 'owners:' || o.id AS object
             FROM owners o CROSS JOIN principals p",
        );
        case.loading_from_rows = from_rows;
        let run =
            support::parity::run_before(&cluster, &case, core::time::Duration::from_secs(300))
                .await;
        assert_postgres(
            &case,
            &run,
            "mixed",
            "orders:o1",
            ActionStatement::Select,
            false,
        );
        assert_postgres(
            &case,
            &run,
            "reader",
            "orders:o1",
            ActionStatement::Select,
            true,
        );
        assert_agrees(&case, &run);
    }
}

#[cfg(all(not(target_os = "windows"), feature = "client"))]
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn indirect_membership_composite_owner_keys_preserve_tenant_identity() {
    use rls2fga::types::ActionStatement;
    use support::parity::{assert_agrees, assert_postgres, Cluster, ParityCase, Principal};

    let cluster = Cluster::start().await;
    let schema = "
        CREATE TABLE principals (id TEXT PRIMARY KEY);
        CREATE TABLE owners (tenant TEXT, id TEXT, PRIMARY KEY (tenant, id));
        CREATE TABLE orders (id TEXT PRIMARY KEY);
        CREATE TABLE ancestors (
            ownable TEXT REFERENCES orders(id), owner_tenant TEXT, owner_id TEXT,
            FOREIGN KEY (owner_tenant, owner_id) REFERENCES owners (tenant, id),
            PRIMARY KEY (ownable, owner_tenant, owner_id));
        CREATE TABLE memberships (
            tenant TEXT, owner_id TEXT, member_id TEXT REFERENCES principals(id), role TEXT,
            FOREIGN KEY (tenant, owner_id) REFERENCES owners (tenant, id),
            PRIMARY KEY (tenant, owner_id, member_id));
        ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
        CREATE POLICY orders_read ON orders FOR SELECT USING (
            EXISTS (SELECT 1 FROM ancestors a WHERE a.ownable = orders.id
                AND EXISTS (SELECT 1 FROM memberships m WHERE m.tenant = a.owner_tenant
                    AND m.owner_id = a.owner_id AND m.member_id = current_setting('app.user_id', true)
                    AND m.role IN ('read', 'admin'))));";
    for from_rows in [false, true] {
        let mut case = ParityCase::reading(
            &format!("indirect-composite-{from_rows}"),
            schema,
            &[
                "INSERT INTO principals VALUES ('reader'), ('other'), ('swapped');
                 INSERT INTO owners VALUES ('t1','x'), ('t2','x'), ('x','t1');
                 INSERT INTO orders VALUES ('o1'), ('o2'), ('o3');
                 INSERT INTO ancestors VALUES ('o1','t1','x'), ('o2','t2','x'), ('o3','x','t1');
                 INSERT INTO memberships VALUES
                    ('t1','x','reader','read'), ('t2','x','other','admin'), ('x','t1','swapped','read');
                 CREATE ROLE app_reader LOGIN;
                 GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_reader;",
            ],
            ["reader", "other", "swapped"].iter().map(|subject| {
                Principal::with_setting(subject, "app_reader", "app.user_id", subject)
            }).collect(),
        ).with_attributes(ATTRIBUTES);
        case.loading_from_rows = from_rows;
        let run =
            support::parity::run_before(&cluster, &case, core::time::Duration::from_secs(300))
                .await;
        for (subject, object) in [
            ("reader", "orders:o1"),
            ("other", "orders:o2"),
            ("swapped", "orders:o3"),
        ] {
            assert_postgres(&case, &run, subject, object, ActionStatement::Select, true);
        }
        assert_agrees(&case, &run);
    }
}

#[test]
fn an_unreadable_hop_denies_and_discloses_the_gap() {
    for table in ["ownable_ancestors", "memberships"] {
        let outputs = outputs(
            SCHEMA,
            &format!(
                "ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
                 CREATE POLICY orders_read ON orders FOR SELECT USING ({NESTED});"
            ),
        );
        assert!(
            outputs.notes().iter().any(|note| matches!(
                note,
                TranslationNote::MembershipTableGrantsNoReads { join_table, .. }
                    if join_table.name() == table
            )),
            "{}",
            outputs.report()
        );
        assert!(
            outputs.translation().relations().iter().any(|relation| {
                relation.type_name.as_str() == "orders"
                    && relation.relation.as_str() == "can_select"
                    && relation.grants_nobody
            }),
            "{}",
            outputs.model()
        );
        if table == "ownable_ancestors" {
            assert_eq!(
                row_records(
                    &outputs,
                    "ownable_ancestors",
                    &serde_json::json!({"ownable":"o1","owner":"ancestor"}),
                ),
                []
            );
        }
    }
}

#[test]
fn a_row_decidable_closure_filter_decides_the_record() {
    let schema = SCHEMA.replace(
        "ownable TEXT NOT NULL REFERENCES ownables(id),",
        "ownable TEXT NOT NULL REFERENCES ownables(id), kind TEXT,",
    );
    let predicate = NESTED.replace(
        "a.ownable = orders.id",
        "a.ownable = orders.id AND a.kind = 'active'",
    );
    let outputs = outputs(
        &schema,
        &format!("CREATE POLICY orders_read ON orders FOR SELECT USING ({predicate});"),
    );
    let closure = row_records(
        &outputs,
        "ownable_ancestors",
        &serde_json::json!({"ownable":"o1","owner":"ancestor","kind":"active"}),
    );
    assert_eq!(closure.len(), 1, "{}", outputs.report());
    assert_eq!(closure[0].object, "orders:o1");
    assert_eq!(closure[0].subject, "owners:ancestor");
    for kind in [serde_json::json!("inactive"), serde_json::Value::Null] {
        assert_eq!(
            row_records(
                &outputs,
                "ownable_ancestors",
                &serde_json::json!({"ownable":"o1","owner":"ancestor","kind":kind}),
            ),
            [],
            "{}",
            outputs.report()
        );
    }
}

#[test]
fn a_sql_only_closure_filter_replays_for_its_guarded_object() {
    let predicate = NESTED.replace(
        "a.ownable = orders.id",
        "a.ownable = orders.id AND lower(a.ownable) = 'o1'",
    );
    let outputs = outputs(
        SCHEMA,
        &format!("CREATE POLICY orders_read ON orders FOR SELECT USING ({predicate});"),
    );
    let description = outputs
        .tuple_queries()
        .iter()
        .filter_map(|query| query.description.as_ref())
        .find(|description| {
            matches!(&description.derivation, RecordDerivation::Joined { .. })
                && description
                    .tables
                    .iter()
                    .any(|table| table.name() == "ownable_ancestors")
        })
        .expect("the closure filter needs SQL evaluation");
    assert!(!description.is_pure());
    let RecordDerivation::Joined { queries, .. } = &description.derivation else {
        unreachable!();
    };
    assert_eq!(queries.len(), 1);
    assert!(matches!(
        queries[0].scope(),
        ReplayScope::Object { object_type, .. } if object_type.as_str() == "orders"
    ));
}

#[test]
fn a_composite_guarded_key_bridges_its_full_owner() {
    let schema = "
        CREATE TABLE principals (id TEXT PRIMARY KEY);
        CREATE TABLE owners (id TEXT PRIMARY KEY);
        CREATE TABLE ownables (id TEXT PRIMARY KEY, owner_id TEXT REFERENCES owners(id));
        CREATE TABLE orders (
            ownable TEXT NOT NULL REFERENCES ownables(id),
            owner TEXT NOT NULL REFERENCES owners(id),
            title TEXT,
            PRIMARY KEY (ownable, owner));
        CREATE TABLE ownable_ancestors (
            ownable TEXT NOT NULL,
            owner TEXT NOT NULL REFERENCES owners(id),
            PRIMARY KEY (ownable, owner),
            FOREIGN KEY (ownable, owner) REFERENCES orders (ownable, owner));
        CREATE TABLE memberships (
            owner_id TEXT NOT NULL REFERENCES owners(id),
            member_id TEXT NOT NULL REFERENCES principals(id),
            role TEXT NOT NULL,
            PRIMARY KEY (owner_id, member_id));
        ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
        CREATE POLICY orders_read ON orders FOR SELECT USING (EXISTS (
            SELECT 1 FROM ownable_ancestors a WHERE a.ownable = orders.ownable
            AND a.owner = orders.owner
            AND EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = a.owner
                AND m.member_id = current_setting('app.user_id', true) AND m.role = 'read')));
    ";
    let outputs = outputs(schema, "");
    let closure = row_records(
        &outputs,
        "ownable_ancestors",
        &serde_json::json!({"ownable":"o1","owner":"ancestor"}),
    );
    assert_eq!(closure.len(), 1, "{}", outputs.report());
    assert_eq!(closure[0].object, "orders:o1|ancestor");
    assert_eq!(closure[0].subject, "owners:ancestor");
    assert_eq!(
        row_records(
            &outputs,
            "ownable_ancestors",
            &serde_json::json!({"ownable":"o1","owner":null}),
        ),
        [],
        "{}",
        outputs.report()
    );
    let members = row_records(
        &outputs,
        "memberships",
        &serde_json::json!({"owner_id":"ancestor","member_id":"reader","role":"read"}),
    );
    assert_eq!(members.len(), 1, "{}", outputs.report());
    assert_eq!(members[0].object, "owners:ancestor");
    assert!(
        outputs.translation().relations().iter().any(|relation| {
            relation.type_name.as_str() == "orders"
                && relation.relation.as_str() == "can_select"
                && !relation.grants_nobody
        }),
        "{}",
        outputs.model()
    );
}

#[test]
fn a_quoted_owner_column_stays_escaped_in_the_records() {
    let schema = SCHEMA.replace(
        "owner TEXT NOT NULL REFERENCES owners(id),\n    PRIMARY KEY (ownable, owner)",
        r#""Owner" TEXT NOT NULL REFERENCES owners(id),
    PRIMARY KEY (ownable, "Owner")"#,
    );
    let predicate = NESTED.replace("m.owner_id = a.owner", r#"m.owner_id = a."Owner""#);
    let outputs = outputs(
        &schema,
        &format!("CREATE POLICY orders_read ON orders FOR SELECT USING ({predicate});"),
    );
    let closure = row_records(
        &outputs,
        "ownable_ancestors",
        &serde_json::json!({"ownable":"o1","Owner":"ancestor"}),
    );
    assert_eq!(closure.len(), 1, "{}", outputs.report());
    assert_eq!(closure[0].subject, "owners:ancestor");
    assert_eq!(
        row_records(
            &outputs,
            "ownable_ancestors",
            &serde_json::json!({"ownable":"o1","Owner":null}),
        ),
        [],
        "{}",
        outputs.report()
    );
}

#[test]
fn two_closure_policies_share_the_link_and_split_the_members() {
    let delete = NESTED.replace("m.role = 'read'", "m.role = 'write'");
    let outputs = outputs(
        SCHEMA,
        &format!(
            "CREATE POLICY orders_read ON orders FOR SELECT USING ({NESTED});
             CREATE POLICY orders_delete ON orders FOR DELETE USING ({delete});"
        ),
    );
    let closure = row_records(
        &outputs,
        "ownable_ancestors",
        &serde_json::json!({"ownable":"o1","owner":"ancestor"}),
    );
    assert_eq!(
        closure.len(),
        1,
        "one link source serves both policies\n{}",
        outputs.report()
    );
    let read = row_records(
        &outputs,
        "memberships",
        &serde_json::json!({"owner_id":"ancestor","member_id":"reader","role":"read"}),
    );
    let write = row_records(
        &outputs,
        "memberships",
        &serde_json::json!({"owner_id":"ancestor","member_id":"writer","role":"write"}),
    );
    assert_eq!(read.len(), 1, "{}", outputs.report());
    assert_eq!(write.len(), 1, "{}", outputs.report());
    assert_ne!(read[0].relation, write[0].relation, "{}", outputs.model());
    assert_eq!(
        row_records(
            &outputs,
            "memberships",
            &serde_json::json!({"owner_id":"ancestor","member_id":"admin","role":"admin"}),
        ),
        [],
        "{}",
        outputs.report()
    );
    for action in ["can_select", "can_delete"] {
        let relation = outputs
            .translation()
            .relations()
            .iter()
            .find(|relation| {
                relation.type_name.as_str() == "orders" && relation.relation.as_str() == action
            })
            .unwrap();
        assert!(!relation.grants_nobody, "{}", outputs.model());
    }
}

#[test]
fn a_listed_role_with_a_guard_keeps_each_variant_separate() {
    let schema = SCHEMA.replace(
        "PRIMARY KEY (owner_id, member_id));",
        "active BOOLEAN,\n    PRIMARY KEY (owner_id, member_id));",
    );
    let predicate = NESTED.replace(
        "m.role = 'read'",
        "m.role IN ('read', 'write') AND m.active = true",
    );
    let outputs = outputs(
        &schema,
        &format!("CREATE POLICY orders_read ON orders FOR SELECT USING ({predicate});"),
    );
    let read = row_records(
        &outputs,
        "memberships",
        &serde_json::json!({"owner_id":"ancestor","member_id":"reader","role":"read","active":true}),
    );
    let write = row_records(
        &outputs,
        "memberships",
        &serde_json::json!({"owner_id":"ancestor","member_id":"writer","role":"write","active":true}),
    );
    assert_eq!(read.len(), 1, "{}", outputs.report());
    assert_eq!(write.len(), 1, "{}", outputs.report());
    assert_ne!(read[0].relation, write[0].relation, "{}", outputs.model());
    for row in [
        serde_json::json!({"owner_id":"ancestor","member_id":"reader","role":"read","active":false}),
        serde_json::json!({"owner_id":"ancestor","member_id":"reader","role":"admin","active":true}),
    ] {
        assert_eq!(
            row_records(&outputs, "memberships", &row),
            [],
            "{}",
            outputs.report()
        );
    }
}

#[test]
fn a_definer_bypass_reads_the_guarded_hop() {
    let schema = format!(
        "{SCHEMA}
        ALTER TABLE ownable_ancestors ENABLE ROW LEVEL SECURITY;
        CREATE POLICY hop_guarded ON ownable_ancestors FOR SELECT USING (current_user = 'restricted');
        CREATE ROLE hop_owner BYPASSRLS;
        CREATE FUNCTION closure_read(order_ownable TEXT) RETURNS BOOLEAN
            LANGUAGE sql STABLE SECURITY DEFINER
            SET search_path TO public, pg_catalog, pg_temp
            AS 'SELECT EXISTS (
                SELECT 1 FROM ownable_ancestors a WHERE a.ownable = order_ownable
                AND EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = a.owner
                    AND m.member_id = current_setting(''app.user_id'', true)
                    AND m.role = ''read''))';
        ALTER FUNCTION closure_read(TEXT) OWNER TO hop_owner;
        CREATE POLICY orders_read ON orders FOR SELECT USING (closure_read(orders.id));"
    );
    let outputs = outputs(&schema, "");
    assert!(
        !outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::MembershipTableGuarded { join_table, .. }
                if join_table.name() == "ownable_ancestors"
        )),
        "the definer bypasses the hop policy\n{}",
        outputs.report()
    );
    assert!(
        outputs.translation().relations().iter().any(|relation| {
            relation.type_name.as_str() == "orders"
                && relation.relation.as_str() == "can_select"
                && !relation.grants_nobody
        }),
        "{}",
        outputs.model()
    );
    let closure = row_records(
        &outputs,
        "ownable_ancestors",
        &serde_json::json!({"ownable":"o1","owner":"ancestor"}),
    );
    assert_eq!(closure.len(), 1, "{}", outputs.report());
    assert_eq!(closure[0].object, "orders:o1");
    assert_eq!(closure[0].subject, "owners:ancestor");
}

#[cfg(all(not(target_os = "windows"), feature = "client"))]
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn indirect_membership_request_gated_hop_live_parity() {
    use rls2fga::types::ActionStatement;
    use support::parity::{assert_agrees, assert_postgres, Cluster, ParityCase, Principal};

    const GATE_ATTRIBUTES: &str =
        r#"[{"key":"app.user_id","kind":"caller_id"},{"key":"app.roles","kind":"set_attribute"}]"#;
    let cluster = Cluster::start().await;
    for table in ["ownable_ancestors", "memberships"] {
        let schema = format!(
        "{SCHEMA}
        ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
        CREATE POLICY hop_open ON {table} FOR SELECT USING (TRUE);
        CREATE POLICY hop_gate ON {table} AS RESTRICTIVE FOR SELECT USING ('read' = ANY(string_to_array(current_setting('app.roles', true), ',')));
        CREATE POLICY orders_read ON orders FOR SELECT USING ({NESTED});"
    );
        for from_rows in [false, true] {
            let mut reader =
                Principal::with_setting("reader", "app_reader", "app.user_id", "reader");
            reader
                .session
                .push(("app.roles".to_string(), "read,write".to_string()));
            reader.context = serde_json::json!({"app_roles": ["read", "write"]});
            let mut gateless =
                Principal::with_setting("gateless", "app_reader", "app.user_id", "gateless");
            gateless.context = serde_json::json!({"app_roles": []});
            let mut outsider =
                Principal::with_setting("outsider", "app_reader", "app.user_id", "outsider");
            outsider
                .session
                .push(("app.roles".to_string(), "read".to_string()));
            outsider.context = serde_json::json!({"app_roles": ["read"]});
            let mut case = ParityCase::reading(
            &format!("indirect-gate-{table}-{from_rows}"),
            &schema,
            &[
                "INSERT INTO principals VALUES ('reader'), ('gateless'), ('outsider');
                 INSERT INTO owners VALUES ('ancestor');
                 INSERT INTO ownables VALUES ('o1','ancestor');
                 INSERT INTO orders VALUES ('o1','first');
                 INSERT INTO ownable_ancestors VALUES ('o1','ancestor');
                 INSERT INTO memberships VALUES ('ancestor','reader','read'), ('ancestor','gateless','read');
                 CREATE ROLE app_reader LOGIN;
                 GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_reader;",
            ],
            vec![reader, gateless, outsider],
        )
        .with_attributes(GATE_ATTRIBUTES);
            case.loading_from_rows = from_rows;
            let run =
                support::parity::run_before(&cluster, &case, core::time::Duration::from_secs(300))
                    .await;
            assert_postgres(
                &case,
                &run,
                "reader",
                "orders:o1",
                ActionStatement::Select,
                true,
            );
            assert_postgres(
                &case,
                &run,
                "gateless",
                "orders:o1",
                ActionStatement::Select,
                false,
            );
            assert_postgres(
                &case,
                &run,
                "outsider",
                "orders:o1",
                ActionStatement::Select,
                false,
            );
            assert_agrees(&case, &run);
        }
    }
}

#[cfg(all(not(target_os = "windows"), feature = "client"))]
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn indirect_membership_sql_residual_live_parity() {
    use rls2fga::types::ActionStatement;
    use support::parity::{assert_agrees, assert_postgres, Cluster, ParityCase, Principal};

    let cluster = Cluster::start().await;
    let predicate = NESTED.replace(
        "a.ownable = orders.id",
        "a.ownable = orders.id AND lower(a.ownable) = 'o1'",
    );
    let schema = format!(
        "{SCHEMA}
        CREATE POLICY orders_read ON orders FOR SELECT USING ({predicate});"
    );
    for from_rows in [false, true] {
        let mut case = ParityCase::reading(
            &format!("indirect-residual-{from_rows}"),
            &schema,
            &["INSERT INTO principals VALUES ('reader');
                 INSERT INTO owners VALUES ('ancestor');
                 INSERT INTO ownables VALUES ('o1','ancestor'), ('o2','ancestor');
                 INSERT INTO orders VALUES ('o1','first'), ('o2','second');
                 INSERT INTO ownable_ancestors VALUES ('o1','ancestor'), ('o2','ancestor');
                 INSERT INTO memberships VALUES ('ancestor','reader','read');
                 CREATE ROLE app_reader LOGIN;
                 GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_reader;"],
            vec![Principal::with_setting(
                "reader",
                "app_reader",
                "app.user_id",
                "reader",
            )],
        )
        .with_attributes(ATTRIBUTES);
        case.loading_from_rows = from_rows;
        let run =
            support::parity::run_before(&cluster, &case, core::time::Duration::from_secs(300))
                .await;
        assert_postgres(
            &case,
            &run,
            "reader",
            "orders:o1",
            ActionStatement::Select,
            true,
        );
        assert_postgres(
            &case,
            &run,
            "reader",
            "orders:o2",
            ActionStatement::Select,
            false,
        );
        assert_agrees(&case, &run);
    }
}

#[cfg(all(not(target_os = "windows"), feature = "client"))]
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn indirect_membership_quoted_owner_column_live_parity() {
    use rls2fga::types::ActionStatement;
    use support::parity::{assert_agrees, assert_postgres, Cluster, ParityCase, Principal};

    let cluster = Cluster::start().await;
    let schema = SCHEMA.replace(
        "owner TEXT NOT NULL REFERENCES owners(id),\n    PRIMARY KEY (ownable, owner)",
        r#""Owner" TEXT NOT NULL REFERENCES owners(id),
    PRIMARY KEY (ownable, "Owner")"#,
    );
    let predicate = NESTED.replace("m.owner_id = a.owner", r#"m.owner_id = a."Owner""#);
    let schema =
        format!("{schema}\nCREATE POLICY orders_read ON orders FOR SELECT USING ({predicate});");
    for from_rows in [false, true] {
        let mut case = ParityCase::reading(
            &format!("indirect-quoted-{from_rows}"),
            &schema,
            &["INSERT INTO principals VALUES ('reader');
                 INSERT INTO owners VALUES ('ancestor');
                 INSERT INTO ownables VALUES ('o1','ancestor');
                 INSERT INTO orders VALUES ('o1','first');
                 INSERT INTO ownable_ancestors VALUES ('o1','ancestor');
                 INSERT INTO memberships VALUES ('ancestor','reader','read');
                 CREATE ROLE app_reader LOGIN;
                 GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_reader;"],
            vec![Principal::with_setting(
                "reader",
                "app_reader",
                "app.user_id",
                "reader",
            )],
        )
        .with_attributes(ATTRIBUTES);
        case.loading_from_rows = from_rows;
        let run =
            support::parity::run_before(&cluster, &case, core::time::Duration::from_secs(300))
                .await;
        assert_postgres(
            &case,
            &run,
            "reader",
            "orders:o1",
            ActionStatement::Select,
            true,
        );
        assert_agrees(&case, &run);
    }
}

#[test]
fn membership_report_keeps_a_quoted_link_name_in_one_table_cell() {
    let quoted_link = "\"ancestry|edge\nrow\"";
    let schema = SCHEMA.replace("ownable_ancestors", quoted_link);
    let predicate = NESTED.replace("ownable_ancestors", quoted_link);
    let outputs = outputs(
        &schema,
        &format!("CREATE POLICY orders_read ON orders FOR SELECT USING ({predicate});"),
    );
    let report = outputs.report();
    let row = report
        .lines()
        .find(|line| line.starts_with("| orders_read "))
        .expect("the report identifies the read policy");
    assert!(row.contains("ancestry\\|edgerow"), "{report}");
    let delimiters = row
        .match_indices('|')
        .filter(|(index, _)| *index == 0 || row.as_bytes()[index - 1] != b'\\')
        .count();
    assert_eq!(delimiters, 5, "{report}");
}
