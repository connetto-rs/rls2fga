//! `current_user` read as the role a request acts as.

use rls2fga::classifier::patterns::PatternClass;

use crate::support;
use crate::support::deployment;

/// One owner column compared with the acting role, rows owned by either acting role and
/// by a name no request acts as.
const DOCS: &str = "
CREATE TABLE docs(id INT PRIMARY KEY, owner TEXT NOT NULL);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner = current_user);
";

/// The owner check of [`DOCS`] spelled inside an invoker function the classifier inlines.
const DOCS_THROUGH_A_FUNCTION: &str = "
CREATE TABLE docs(id INT PRIMARY KEY, owner TEXT NOT NULL);
CREATE FUNCTION owns(o TEXT) RETURNS BOOLEAN LANGUAGE sql AS 'SELECT o = current_user';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owns(owner));
";

/// Under two acting roles `current_user` holds one name per request, so no one literal
/// stands for it and the clause is refused naming both roles, whether the policy spells
/// the keyword or a function body it inlines does.
#[test]
fn two_acting_roles_leave_current_user_refused() {
    let deployment = deployment::caller_deployment_acting_as(&["reader", "writer"], []);
    for schema in [DOCS, DOCS_THROUGH_A_FUNCTION] {
        let (classified, _, _) = support::classify_with(schema, None, &deployment);
        let using = classified[0]
            .using_classification()
            .expect("the policy has a USING clause");
        let PatternClass::Unknown(refused) = &using.pattern else {
            panic!("current_user has no one value, got {:?}", using.pattern);
        };
        assert!(
            refused.reason.contains("acts as 2 roles (reader, writer)"),
            "the refusal names both acting roles, got {:?}",
            refused.reason
        );
    }
}

#[cfg(all(not(target_os = "windows"), feature = "client"))]
mod parity {
    use rls2fga::types::ActionStatement;

    use super::DOCS;
    use crate::support;
    use crate::support::parity::{assert_agrees, assert_postgres, Cluster, ParityCase, Principal};

    /// A deployment acting as one role reads `current_user` as that role's name, so a
    /// request acting as `reader` sees the rows `reader` owns and one acting as `writer`
    /// those `writer` owns, in `PostgreSQL` and in the model alike.
    #[tokio::test]
    #[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
    async fn current_user_names_each_acting_role() {
        let cluster = Cluster::start().await;
        for role in ["reader", "writer"] {
            let case = ParityCase::reading(
                &format!("current-user-{role}"),
                DOCS,
                &[
                    "INSERT INTO docs VALUES (1, 'reader'), (2, 'writer'), (3, 'someone')",
                    "CREATE ROLE reader; CREATE ROLE writer;
                     GRANT SELECT ON docs TO reader, writer",
                ],
                vec![Principal::as_role("alice", role)],
            )
            .acting_as(role);
            let run = support::parity::run(&cluster, &case).await;
            for (object, owner) in [("docs:1", "reader"), ("docs:2", "writer"), ("docs:3", "")] {
                assert_postgres(
                    &case,
                    &run,
                    "alice",
                    object,
                    ActionStatement::Select,
                    owner == role,
                );
            }
            assert_agrees(&case, &run);
        }
    }

    /// A column's name decides nothing once `current_user` is a role literal, so literal,
    /// null, list and clock tests on columns named like owners guard rows as any column's do.
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
