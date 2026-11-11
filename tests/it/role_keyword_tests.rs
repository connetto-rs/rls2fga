//! `current_user` read as the role a request acts as.

use rls2fga::classifier::patterns::{AttributeCondition, ConstantBool, PatternClass};
use rls2fga::types::ConfidenceLevel;

use crate::support;
use crate::support::deployment;
use crate::support::footgun::relation_definition;

/// The two acting roles the cases below run as.
const ACTING_ROLES: &str = "CREATE ROLE reader; CREATE ROLE writer;";

/// One owner column compared with the acting role, rows owned by either acting role and
/// by a name no request acts as.
const DOCS: &str = "
CREATE TABLE docs(id INT PRIMARY KEY, owner TEXT NOT NULL);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner = current_user);
GRANT SELECT ON docs TO reader, writer;
";

/// The owner check of [`DOCS`] spelled inside an invoker function the classifier inlines.
const DOCS_THROUGH_A_FUNCTION: &str = "
CREATE TABLE docs(id INT PRIMARY KEY, owner TEXT NOT NULL);
CREATE FUNCTION owns(o TEXT) RETURNS BOOLEAN LANGUAGE sql AS 'SELECT o = current_user';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owns(owner));
";

/// Each acting role reads `current_user` as its own name, so a policy is classified once
/// per role and each copy compares the column with that role's name, whether the policy
/// spells the keyword or a function body it inlines does.
#[test]
fn each_acting_role_reads_current_user_as_its_own_name() {
    let deployment = deployment::caller_deployment_acting_as(&["reader", "writer"], []);
    for schema in [DOCS, DOCS_THROUGH_A_FUNCTION] {
        let (classified, _, _) =
            support::classify_with(&format!("{ACTING_ROLES}{schema}"), None, &deployment);
        let compared: Vec<(Option<&str>, &str)> = classified
            .iter()
            .map(|policy| {
                let using = policy
                    .using_classification()
                    .expect("the policy has a USING clause");
                let value = match &using.pattern {
                    PatternClass::P9AttributeCondition(AttributeCondition {
                        value_description,
                        ..
                    }) => value_description.as_str(),
                    PatternClass::ExpandedFunction(expanded) => match &expanded.inner.pattern {
                        PatternClass::P9AttributeCondition(AttributeCondition {
                            value_description,
                            ..
                        }) => value_description.as_str(),
                        other => panic!("the inlined body compares a literal, got {other:?}"),
                    },
                    other => panic!("the policy compares a literal, got {other:?}"),
                };
                (policy.acting_role(), value)
            })
            .collect();
        assert_eq!(
            compared,
            [(Some("reader"), "'reader'"), (Some("writer"), "'writer'"),]
        );
    }
}

/// A comparison of `current_user` with a role's name is a constant for each acting role,
/// true for the role it names and false for every other.
#[test]
fn a_role_name_comparison_is_a_constant_per_acting_role() {
    let (classified, _, _) = support::classify_with(
        &format!(
            "{ACTING_ROLES}
             CREATE TABLE docs(id INT PRIMARY KEY);
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
             CREATE POLICY readers ON docs FOR SELECT USING (current_user = 'reader');"
        ),
        None,
        &deployment::caller_deployment_acting_as(&["reader", "writer"], []),
    );
    let constants: Vec<(Option<&str>, bool)> = classified
        .iter()
        .map(|policy| {
            let using = policy
                .using_classification()
                .expect("the policy has a USING clause");
            let PatternClass::P10ConstantBool(ConstantBool { value }) = using.pattern else {
                panic!(
                    "the comparison folds to a constant, got {:?}",
                    using.pattern
                );
            };
            (policy.acting_role(), value)
        })
        .collect();
    assert_eq!(constants, [(Some("reader"), true), (Some("writer"), false)]);
}

/// The model joins each role's branch to the kind a check states, so the rows a request
/// sees follow the role it acts as.
#[test]
fn each_acting_role_gets_its_own_branch() {
    let (classified, db, registry) = support::classify_with(
        &format!("{ACTING_ROLES}{DOCS}"),
        None,
        &deployment::caller_deployment_acting_as(&["reader", "writer"], []),
    );
    let model = support::plan_at(classified, &db, &registry, ConfidenceLevel::B).model();
    let can_select = relation_definition(&model, "docs", "can_select").expect("docs answers reads");
    assert!(
        can_select.contains("acting_reader from request_gate")
            && can_select.contains("acting_writer from request_gate"),
        "each acting role reads through its own branch:\n{model}"
    );
}

#[cfg(all(not(target_os = "windows"), feature = "client"))]
mod parity {
    use rls2fga::types::ActionStatement;

    use super::{ACTING_ROLES, DOCS};
    use crate::support;
    use crate::support::parity::{assert_agrees, assert_postgres, Cluster, ParityCase, Principal};

    /// A deployment acting as two roles reads `current_user` as the role each request runs
    /// as, so `reader` sees the rows `reader` owns and `writer` those `writer` owns, in
    /// `PostgreSQL` and in the model alike.
    #[tokio::test]
    #[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
    async fn current_user_names_each_acting_role() {
        let cluster = Cluster::start().await;
        let case = ParityCase::reading(
            "current-user-per-acting-role",
            DOCS,
            &["INSERT INTO docs VALUES (1, 'reader'), (2, 'writer'), (3, 'someone')"],
            vec![
                Principal::as_role("alice", "reader"),
                Principal::as_role("bob", "writer"),
            ],
        )
        .after(&[ACTING_ROLES]);
        let run = support::parity::run(&cluster, &case).await;
        for (subject, object, visible) in [
            ("alice", "docs:1", true),
            ("alice", "docs:2", false),
            ("bob", "docs:2", true),
            ("bob", "docs:1", false),
            ("alice", "docs:3", false),
        ] {
            assert_postgres(
                &case,
                &run,
                subject,
                object,
                ActionStatement::Select,
                visible,
            );
        }
        assert_agrees(&case, &run);
    }

    /// A comparison of `current_user` with a role's name admits every row to that role and
    /// none to the other, and a gate a membership table reads that way does the same.
    #[tokio::test]
    #[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
    async fn a_role_name_comparison_admits_only_that_role() {
        let cluster = Cluster::start().await;
        let case = ParityCase::reading(
            "role-name-comparison",
            "CREATE TABLE docs(id INT PRIMARY KEY);
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
             CREATE POLICY readers ON docs FOR SELECT USING (current_user = 'reader');",
            &[
                "INSERT INTO docs VALUES (1), (2)",
                &format!("{ACTING_ROLES} GRANT SELECT ON docs TO reader, writer"),
            ],
            vec![
                Principal::as_role("alice", "reader"),
                Principal::as_role("bob", "writer"),
            ],
        );
        let run = support::parity::run(&cluster, &case).await;
        assert_postgres(
            &case,
            &run,
            "alice",
            "docs:1",
            ActionStatement::Select,
            true,
        );
        assert_postgres(&case, &run, "bob", "docs:1", ActionStatement::Select, false);
        assert_agrees(&case, &run);
    }

    /// Literal, null, list and clock tests on columns named like owners guard rows as any
    /// column's do, since a column's name decides nothing once `current_user` is a role.
    #[tokio::test]
    #[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
    async fn user_like_columns_guard_rows_like_any_column() {
        let cluster = Cluster::start().await;
        let case = ParityCase::reading(
            "user-like-column-guards",
            "CREATE TABLE docs(
                 id INT PRIMARY KEY,
                 owner_id TEXT,
                 created_by TEXT,
                 author_id TEXT,
                 owner_id_expires_at TIMESTAMPTZ NOT NULL
             );
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
             CREATE POLICY by_owner ON docs FOR SELECT USING (owner_id = 'alice');
             CREATE POLICY unclaimed ON docs FOR SELECT USING (created_by IS NULL);
             CREATE POLICY by_author ON docs FOR SELECT USING (author_id IN ('bob', 'carol'));
             CREATE POLICY unexpired ON docs FOR SELECT USING (owner_id_expires_at > now());",
            &[
                "INSERT INTO docs VALUES
                     (1, 'alice', 'x', 'x', now() - interval '1 day'),
                     (2, 'x', NULL, 'x', now() - interval '1 day'),
                     (3, 'x', 'x', 'carol', now() - interval '1 day'),
                     (4, 'x', 'x', 'x', now() + interval '1 day'),
                     (5, 'x', 'x', 'x', now() - interval '1 day')",
                "CREATE ROLE reader; GRANT SELECT ON docs TO reader",
            ],
            vec![Principal::as_role("dave", "reader").with_clock()],
        );
        let run = support::parity::run(&cluster, &case).await;
        for (object, visible) in [
            ("docs:1", true),
            ("docs:2", true),
            ("docs:3", true),
            ("docs:4", true),
            ("docs:5", false),
        ] {
            assert_postgres(
                &case,
                &run,
                "dave",
                object,
                ActionStatement::Select,
                visible,
            );
        }
        assert_agrees(&case, &run);
    }
}
