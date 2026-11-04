//! A column compared with the set a declared `SECURITY DEFINER` helper returns becomes
//! the grants the helper's body reads, `role from parent` through each parent arm.

use rls2fga::classifier::function_registry::{SessionAttribute, SessionAttributeKind};
use rls2fga::classifier::patterns::{
    ClassifiedExpr, GrantRows, HelperSetArm, PatternClass, UnclassifiedExpr,
};
use rls2fga::translator::{Translator, TranslatorBuilder};
use rls2fga::types::{AttributeLiteral, AttributePredicate, AttributeTest, ConfidenceLevel};
use rls2fga::types::{ColumnName, TranslationNote};

use crate::support::footgun::{db_of, relation_definition};

/// The request's reduced ownership schema, two levels of grants under the orders.
pub(crate) const LEVELS: &str = "
CREATE TABLE teams (id TEXT PRIMARY KEY);
CREATE TABLE projects (id TEXT PRIMARY KEY, team_id TEXT NOT NULL REFERENCES teams (id));
CREATE TABLE orders (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects (id),
  title TEXT);
CREATE TABLE team_grants (team_id TEXT NOT NULL REFERENCES teams (id), principal_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('read', 'write', 'admin')), PRIMARY KEY (team_id, principal_id));
CREATE TABLE project_grants (project_id TEXT NOT NULL REFERENCES projects (id), principal_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('read', 'write', 'admin')), PRIMARY KEY (project_id, principal_id));
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
CREATE FUNCTION authz.teams_with(min_role TEXT) RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT g.team_id FROM public.team_grants g
  WHERE g.principal_id = current_setting('app.user_id', true)
    AND (g.role = 'admin' OR min_role = 'read' OR (min_role = 'write' AND g.role = 'write'))
$$;
CREATE FUNCTION authz.projects_with(min_role TEXT) RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT g.project_id FROM public.project_grants g
  WHERE g.principal_id = current_setting('app.user_id', true)
    AND (g.role = 'admin' OR min_role = 'read' OR (min_role = 'write' AND g.role = 'write'))
  UNION
  SELECT p.id FROM public.projects p WHERE p.team_id IN (SELECT authz.teams_with(min_role))
$$;
ALTER FUNCTION authz.teams_with(TEXT) OWNER TO authz_owner;
ALTER FUNCTION authz.projects_with(TEXT) OWNER TO authz_owner;
GRANT USAGE ON SCHEMA authz TO authz_owner;
";

/// What the owner reads, without which every call raises `42501`.
pub(crate) const OWNER_READS: &str =
    "GRANT SELECT ON team_grants, project_grants, projects TO authz_owner;";

/// The request's two policies on `orders`.
pub(crate) const ORDERS: &str = "
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY orders_read ON orders FOR SELECT USING (
  project_id = ANY (ARRAY(SELECT authz.projects_with('read'))));
CREATE POLICY orders_update ON orders FOR UPDATE
  USING (project_id = ANY (ARRAY(SELECT authz.projects_with('write'))))
  WITH CHECK (project_id = ANY (ARRAY(SELECT authz.projects_with('write'))));
";

/// Both level helpers declared.
const BOTH: &[&str] = &["authz.projects_with", "authz.teams_with"];

/// The caller, and a scalar the request carries, which no helper may take its caller from.
fn translator(min_confidence: ConfidenceLevel, helpers: &[&str]) -> Translator {
    TranslatorBuilder::new()
        .with_min_confidence(min_confidence)
        .with_session_attributes([
            SessionAttribute::setting("app.user_id", SessionAttributeKind::CallerId),
            SessionAttribute::setting("app.tenant", SessionAttributeKind::ScalarAttribute),
        ])
        .with_declared_helpers(helpers)
        .build()
}

fn model(sql: &str, helpers: &[&str]) -> String {
    translator(ConfidenceLevel::B, helpers)
        .translate(&db_of(sql))
        .expect("the schema should plan")
        .outputs()
        .expect("every clause should translate")
        .model()
        .clone()
}

/// The `USING` classification of the policy named `policy`.
fn using_of(sql: &str, helpers: &[&str], policy: &str) -> ClassifiedExpr {
    translator(ConfidenceLevel::B, helpers)
        .classify(&db_of(sql))
        .into_iter()
        .find(|classified| classified.name() == policy)
        .unwrap_or_else(|| panic!("{policy} should classify"))
        .using_classification()
        .expect("USING should classify")
        .clone()
}

fn refusal_of(sql: &str, helpers: &[&str], policy: &str) -> String {
    let classified = using_of(sql, helpers, policy);
    assert_eq!(classified.confidence, ConfidenceLevel::D, "{classified:?}");
    match classified.pattern {
        PatternClass::Unknown(UnclassifiedExpr { reason, .. }) => reason,
        other => panic!("{policy} should be refused, got {other:?}"),
    }
}

#[test]
fn the_reduced_schema_reads_each_role_from_its_parent() {
    assert_eq!(
        model(&format!("{LEVELS}{OWNER_READS}{ORDERS}"), BOTH),
        "model
  schema 1.1

type user

type nobody

type orders
  relations
    define no_access: [nobody]
    define projects: [projects]
    define can_delete: no_access
    define can_insert: no_access
    define can_select: projects_with_read from projects
    define can_select_for_update: can_update
    define can_update: projects_with_write from projects and can_select
    define can_update_without_reading: projects_with_write from projects

type projects
  relations
    define admin: [user]
    define read: [user]
    define teams: [teams]
    define write: [user]
    define projects_with_read: read or write or admin or teams_with_read from teams
    define projects_with_write: write or admin or teams_with_write from teams

type teams
  relations
    define admin: [user]
    define read: [user]
    define write: [user]
    define teams_with_read: read or write or admin
    define teams_with_write: write or admin
"
    );
}

/// Every call reads the same role relations, so one grant row is one tuple however many
/// calls admit its role.
#[test]
fn each_grant_row_is_loaded_once() {
    let outputs = translator(ConfidenceLevel::B, BOTH)
        .translate(&db_of(&format!("{LEVELS}{OWNER_READS}{ORDERS}")))
        .expect("the schema should plan")
        .outputs()
        .expect("every clause should translate");
    for table in ["team_grants", "project_grants"] {
        let mut roles: Vec<&str> = outputs
            .tuple_queries()
            .iter()
            .filter(|query| query.sql.contains(&format!("FROM \"public\".\"{table}\"")))
            .map(|query| {
                let (_, role) = query
                    .sql
                    .rsplit_once("\"role\" = ")
                    .expect("each grant query keeps one role");
                role
            })
            .collect();
        roles.sort_unstable();
        assert_eq!(roles, ["'admin');", "'read');", "'write');"], "{table}");
    }
}

#[test]
fn a_policy_on_the_level_itself_reads_the_call_relation() {
    let sql = format!(
        "{LEVELS}{OWNER_READS}
         ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
         CREATE POLICY projects_read ON projects FOR SELECT USING (
           id = ANY (ARRAY(SELECT authz.projects_with('read'))));"
    );
    assert_eq!(
        relation_definition(&model(&sql, BOTH), "projects", "can_select").as_deref(),
        Some("projects_with_read")
    );
}

#[test]
fn every_spelling_of_set_membership_reads_alike() {
    let spelled = |membership: &str| {
        model(
            &format!(
                "{LEVELS}{OWNER_READS}
                 ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
                 CREATE POLICY orders_read ON orders FOR SELECT USING ({membership});"
            ),
            BOTH,
        )
    };
    let array = spelled("project_id = ANY (ARRAY(SELECT authz.projects_with('read')))");
    assert_eq!(
        spelled("orders.project_id IN (SELECT authz.projects_with('read'))"),
        array
    );
    assert_eq!(
        spelled("project_id = ANY (SELECT authz.projects_with('read'))"),
        array
    );
    assert_eq!(
        spelled("(project_id) = ANY (ARRAY(SELECT authz.projects_with('read')))"),
        array
    );
}

#[test]
fn an_owner_lacking_select_is_refused_naming_the_table() {
    let sql = format!("{LEVELS}{ORDERS}");
    let notes = translator(ConfidenceLevel::D, BOTH)
        .translate(&db_of(&sql))
        .expect("the schema should plan")
        .outputs_accepting_gaps()
        .notes()
        .to_vec();
    let refused = notes.iter().any(|note| {
        matches!(
            note,
            TranslationNote::ExpressionRefused { policy, reason }
                if policy == "orders_read"
                    && reason.contains("authz.projects_with")
                    && reason.contains("lacks SELECT on `project_grants`")
        )
    });
    assert!(refused, "{notes:#?}");
}

#[test]
fn an_undeclared_definer_helper_stays_refused() {
    let classified = using_of(
        &format!("{LEVELS}{OWNER_READS}{ORDERS}"),
        &[],
        "orders_read",
    );
    assert!(
        matches!(classified.pattern, PatternClass::Unknown(_)),
        "{classified:?}"
    );
    assert_eq!(classified.confidence, ConfidenceLevel::D);
}

#[test]
fn a_parent_arm_reaching_an_undeclared_helper_is_refused_naming_it() {
    let reason = refusal_of(
        &format!("{LEVELS}{OWNER_READS}{ORDERS}"),
        &["authz.projects_with"],
        "orders_read",
    );
    assert!(reason.contains("'authz.teams_with'"), "{reason}");
}

#[test]
fn a_union_of_calls_is_refused() {
    let sql = format!(
        "{LEVELS}{OWNER_READS}
         CREATE FUNCTION authz.owners_with(min_role TEXT) RETURNS SETOF TEXT
         LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
           SELECT authz.teams_with(min_role) UNION SELECT authz.projects_with(min_role)
         $$;
         ALTER FUNCTION authz.owners_with(TEXT) OWNER TO authz_owner;
         ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
         CREATE POLICY orders_read ON orders FOR SELECT USING (
           project_id = ANY (ARRAY(SELECT authz.owners_with('read'))));"
    );
    let reason = refusal_of(
        &sql,
        &[
            "authz.owners_with",
            "authz.projects_with",
            "authz.teams_with",
        ],
        "orders_read",
    );
    assert!(reason.contains("authz.owners_with"), "{reason}");
}

/// A column the helper returns that names another table's rows than the compared one
/// would grant on a key of the wrong table.
#[test]
fn a_column_naming_other_rows_is_refused() {
    let sql = format!(
        "{LEVELS}{OWNER_READS}
         ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
         CREATE POLICY orders_read ON orders FOR SELECT USING (
           project_id = ANY (ARRAY(SELECT authz.teams_with('read'))));"
    );
    let reason = refusal_of(&sql, BOTH, "orders_read");
    assert!(
        reason.contains("'projects'") && reason.contains("'teams'"),
        "{reason}"
    );
}

/// The project grant table's role column as the reduced schema declares it.
const PROJECT_ROLE: &str =
    "project_grants (project_id TEXT NOT NULL REFERENCES projects (id), principal_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('read', 'write', 'admin'))";

/// A role column whose values no `NOT NULL` column closed by literals bounds is not
/// split into roles, so the rows are kept by the body's own condition. A wrong split
/// would grant the roles the check seems to list rather than the ones rows hold.
#[test]
fn a_role_column_not_closed_to_literals_keeps_the_body_condition() {
    let role = |definition: &str| {
        PROJECT_ROLE.replace(
            "role TEXT NOT NULL CHECK (role IN ('read', 'write', 'admin'))",
            definition,
        )
    };
    let cases = [
        ("nullable", role("role TEXT CHECK (role IN ('read', 'write', 'admin'))"), ""),
        ("lowered", role("role TEXT NOT NULL CHECK (lower(role) IN ('read', 'write', 'admin'))"), ""),
        ("computed element", role("role TEXT NOT NULL CHECK (role IN ('read', 'write', lower('ADMIN')))"), ""),
        ("renaming cast", role("role TEXT NOT NULL CHECK (role::varchar(4) IN ('read', 'writ', 'admi'))"), ""),
        ("no list", role("role TEXT NOT NULL CHECK (length(role) > 0)"), ""),
        // `NULL` in the list lets any value pass the check.
        ("null element", role("role TEXT NOT NULL CHECK (role IN ('read', 'write', 'admin', NULL))"), ""),
        ("array literal", role("role TEXT NOT NULL CHECK (role = ANY ('{read,write,admin}'::text[]))"), ""),
        (
            "two closed columns",
            role("role TEXT NOT NULL CHECK (role IN ('read', 'write', 'admin')), kind TEXT NOT NULL CHECK (kind IN ('person'))"),
            "",
        ),
        (
            "not validated",
            role("role TEXT NOT NULL"),
            "ALTER TABLE project_grants ADD CONSTRAINT role_closed
               CHECK (role IN ('read', 'write', 'admin')) NOT VALID;",
        ),
    ];
    for (case, project_grants, after) in cases {
        let sql =
            format!("{LEVELS}{after}{OWNER_READS}{ORDERS}").replace(PROJECT_ROLE, &project_grants);
        let PatternClass::P20DeclaredHelper(helper) = using_of(&sql, BOTH, "orders_update").pattern
        else {
            panic!("{case}: orders_update should translate");
        };
        let HelperSetArm::Grant(grant) = &helper.call.arms[0] else {
            panic!("{case}: the first arm reads the grants");
        };
        assert_eq!(
            grant.rows,
            GrantRows::Matching {
                predicate: Some(AttributePredicate {
                    column: ColumnName::from_stored("role"),
                    test: AttributeTest::In(vec![
                        AttributeLiteral::Text("admin".into()),
                        AttributeLiteral::Text("write".into()),
                    ]),
                }),
            },
            "{case}"
        );
    }
}

/// `pg_dump` writes the role check as `= ANY (ARRAY[...])`, every literal cast to `text`,
/// and the policy with the literal cast and the call aliased.
#[test]
fn the_dumped_spelling_reads_as_the_written_one() {
    let written = model(&format!("{LEVELS}{OWNER_READS}{ORDERS}"), BOTH);
    let dumped = format!("{LEVELS}{OWNER_READS}{ORDERS}")
        .replace(
            "CHECK (role IN ('read', 'write', 'admin'))",
            // `read` twice, which the closed domain holds once.
            "CONSTRAINT role_check CHECK ((role = ANY (ARRAY['read'::text, 'write'::text, 'admin'::text, 'read'::text])))",
        )
        .replace(
            "project_id = ANY (ARRAY(SELECT authz.projects_with('read')))",
            "(project_id = ANY (ARRAY( SELECT authz.projects_with('read'::text) AS projects_with)))",
        );
    assert_eq!(model(&dumped, BOTH), written);
}

/// The report names the pattern by its README row.
#[test]
fn the_report_names_the_helper_call() {
    let report = translator(ConfidenceLevel::B, BOTH)
        .translate(&db_of(&format!("{LEVELS}{OWNER_READS}{ORDERS}")))
        .expect("the schema should plan")
        .outputs()
        .expect("every clause should translate")
        .report();
    assert!(
        report.contains("P20 (project_id in authz.projects_with('read'))"),
        "{report}"
    );
}

/// Every shape outside the one the helper's answer proves falls closed, each naming why
/// where the helper is the reason.
#[test]
fn every_unproven_call_is_refused() {
    let policy = |using: &str| {
        format!(
            "{LEVELS}{OWNER_READS}
             CREATE FUNCTION authz.misparented(min_role TEXT) RETURNS SETOF TEXT
             LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
               SELECT p.id FROM public.projects p WHERE p.team_id IN (SELECT authz.projects_with(min_role))
             $$;
             CREATE FUNCTION authz.tenant_teams() RETURNS SETOF TEXT
             LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
               SELECT g.team_id FROM public.team_grants g WHERE g.principal_id = current_setting('app.tenant', true)
             $$;
             CREATE FUNCTION authz.mixed() RETURNS SETOF TEXT
             LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
               SELECT g.team_id FROM public.team_grants g WHERE g.principal_id = current_setting('app.user_id', true)
               UNION
               SELECT g.project_id FROM public.project_grants g WHERE g.principal_id = current_setting('app.user_id', true)
             $$;
             ALTER FUNCTION authz.misparented(TEXT) OWNER TO authz_owner;
             ALTER FUNCTION authz.tenant_teams() OWNER TO authz_owner;
             ALTER FUNCTION authz.mixed() OWNER TO authz_owner;
             ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
             ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
             CREATE POLICY orders_read ON orders FOR SELECT USING ({using});
             CREATE POLICY projects_read ON projects FOR SELECT USING ({using});"
        )
    };
    let helpers = [
        "authz.projects_with",
        "authz.teams_with",
        "authz.misparented",
        "authz.tenant_teams",
        "authz.mixed",
    ];
    let named = [
        (
            "orders_read",
            "project_id = ANY (ARRAY(SELECT authz.projects_with(current_setting('app.tenant', true))))",
            "which is not a literal",
        ),
        (
            "orders_read",
            "title = ANY (ARRAY(SELECT authz.mixed()))",
            "names no row",
        ),
        (
            "projects_read",
            "team_id = ANY (ARRAY(SELECT authz.misparented('read')))",
            "column 'team_id' names rows of 'teams'",
        ),
        (
            "projects_read",
            "team_id = ANY (ARRAY(SELECT authz.tenant_teams()))",
            "not the caller",
        ),
        (
            "orders_read",
            "project_id = ANY (ARRAY(SELECT authz.projects_with(min_role => 'read')))",
            "which is not a literal",
        ),
    ];
    for (target, using, reason) in named {
        let refused = refusal_of(&policy(using), &helpers, target);
        assert!(refused.contains(reason), "`{using}`: {refused}");
    }

    let overloaded = format!(
        "{}
         CREATE FUNCTION authz.projects_with(min_role INT) RETURNS SETOF TEXT
         LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$ SELECT NULL::text $$;",
        policy("project_id = ANY (ARRAY(SELECT authz.projects_with('read')))")
    );
    let refused = refusal_of(&overloaded, &helpers, "orders_read");
    assert!(refused.contains("more than one declaration"), "{refused}");

    for using in [
        "NOT (project_id = ANY (ARRAY(SELECT authz.projects_with('read'))))",
        "lower(project_id) = ANY (ARRAY(SELECT authz.projects_with('read')))",
        "public.orders.project_id = ANY (ARRAY(SELECT authz.projects_with('read')))",
        "project_id IN (SELECT 'P1')",
        "project_id = ANY (ARRAY(SELECT current_date))",
    ] {
        refusal_of(&policy(using), &helpers, "orders_read");
    }

    // A column whose foreign keys name two tables, or a non-key, names no one row.
    for keys in [
        "ALTER TABLE orders ADD FOREIGN KEY (project_id) REFERENCES teams (id);",
        "ALTER TABLE projects ADD COLUMN code TEXT NOT NULL UNIQUE;
         ALTER TABLE orders ADD FOREIGN KEY (project_id) REFERENCES projects (code);",
    ] {
        let sql = format!(
            "{}{keys}",
            policy("project_id = ANY (ARRAY(SELECT authz.projects_with('read')))")
        );
        let refused = refusal_of(&sql, &helpers, "orders_read");
        assert!(refused.contains("names no row"), "{keys}: {refused}");
    }
}

/// A call keeping no role the closed column can hold returns nothing, through its
/// parent arm too, and a compared table whose rows have no key has nothing to bridge.
#[test]
fn a_call_returning_nothing_denies() {
    let sql = |orders: &str, using: &str| {
        format!(
            "{}{OWNER_READS}
             CREATE FUNCTION authz.teams_as(r TEXT) RETURNS SETOF TEXT
             LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
               SELECT g.team_id FROM public.team_grants g
               WHERE g.principal_id = current_setting('app.user_id', true) AND g.role = r
             $$;
             CREATE FUNCTION authz.projects_as(r TEXT) RETURNS SETOF TEXT
             LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
               SELECT g.project_id FROM public.project_grants g
               WHERE g.principal_id = current_setting('app.user_id', true) AND g.role = r
               UNION
               SELECT p.id FROM public.projects p WHERE p.team_id IN (SELECT authz.teams_as(r))
             $$;
             ALTER FUNCTION authz.teams_as(TEXT) OWNER TO authz_owner;
             ALTER FUNCTION authz.projects_as(TEXT) OWNER TO authz_owner;
             ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
             CREATE POLICY orders_read ON orders FOR SELECT USING ({using});",
            LEVELS.replace(
                "CREATE TABLE orders (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects (id),",
                orders,
            )
        )
    };
    let keyed =
        "CREATE TABLE orders (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects (id),";
    let unkeyed =
        "CREATE TABLE orders (id TEXT, project_id TEXT NOT NULL REFERENCES projects (id),";
    let helpers = ["authz.projects_as", "authz.teams_as"];
    for (orders, using) in [
        (
            keyed,
            "project_id = ANY (ARRAY(SELECT authz.projects_as('owner')))",
        ),
        (
            unkeyed,
            "project_id = ANY (ARRAY(SELECT authz.projects_as('read')))",
        ),
    ] {
        let dsl = translator(ConfidenceLevel::B, &helpers)
            .translate(&db_of(&sql(orders, using)))
            .expect("the schema should plan")
            .outputs_accepting_gaps()
            .model()
            .clone();
        assert_eq!(
            relation_definition(&dsl, "orders", "can_select").as_deref(),
            Some("no_access"),
            "`{using}`: {dsl}"
        );
    }
}

/// Roles of another literal kind, and a condition on a column no check closes, load the
/// rows they keep and no others.
#[test]
fn number_and_boolean_conditions_load_only_the_rows_they_keep() {
    let sql = "
CREATE TABLE docs (id TEXT PRIMARY KEY);
CREATE TABLE doc_levels (doc_id TEXT NOT NULL REFERENCES docs (id), principal_id TEXT NOT NULL,
  level INT NOT NULL CHECK (level IN (1, 2, 3)), PRIMARY KEY (doc_id, principal_id));
CREATE TABLE doc_flags (doc_id TEXT NOT NULL REFERENCES docs (id), principal_id TEXT NOT NULL,
  active BOOLEAN NOT NULL, PRIMARY KEY (doc_id, principal_id));
CREATE ROLE docs_owner NOLOGIN BYPASSRLS;
CREATE FUNCTION docs_kept() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT g.doc_id FROM doc_levels g
  WHERE g.principal_id = current_setting('app.user_id', true) AND (g.level = 2 OR g.level = 03)
  UNION
  SELECT f.doc_id FROM doc_flags f
  WHERE f.principal_id = current_setting('app.user_id', true) AND f.active = true
$$;
ALTER FUNCTION docs_kept() OWNER TO docs_owner;
GRANT SELECT ON doc_levels, doc_flags TO docs_owner;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_read ON docs FOR SELECT USING (id IN (SELECT docs_kept()));
";
    let outputs = translator(ConfidenceLevel::B, &["docs_kept"])
        .translate(&db_of(sql))
        .expect("the schema should plan")
        .outputs()
        .expect("every clause should translate");
    let mut kept: Vec<&str> = outputs
        .tuple_queries()
        .iter()
        .filter(|query| !query.sql.contains("FROM \"public\".\"docs\""))
        .map(|query| {
            query
                .sql
                .rsplit_once("\nAND ")
                .expect("each grant query keeps its condition")
                .1
        })
        .collect();
    kept.sort_unstable();
    assert_eq!(
        kept,
        [
            "(\"active\" IN (TRUE));",
            "(\"level\" = 2);",
            "(\"level\" = 3);"
        ]
    );
}

/// A role the body spells dollar-quoted is the same role.
#[test]
fn a_dollar_quoted_role_reads_as_the_quoted_one() {
    let body = |admin: &str| {
        format!(
            "{LEVELS}{OWNER_READS}
             CREATE FUNCTION authz.admins() RETURNS SETOF TEXT
             LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
               SELECT g.team_id FROM public.team_grants g
               WHERE g.principal_id = current_setting('app.user_id', true) AND g.role = {admin}
             $$;
             ALTER FUNCTION authz.admins() OWNER TO authz_owner;
             ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
             CREATE POLICY teams_read ON teams FOR SELECT USING (
               id = ANY (ARRAY(SELECT authz.admins())));"
        )
    };
    assert_eq!(
        model(&body("$q$admin$q$"), &["authz.admins"]),
        model(&body("'admin'"), &["authz.admins"])
    );
}

/// A helper returning the keys of the rows naming the caller, R100's
/// `installations_of_bot`, grants every such row, on the table those keys belong to.
#[test]
fn a_grant_arm_on_its_own_level_loads_every_row_naming_the_caller() {
    let sql = "
CREATE TABLE installations (id TEXT PRIMARY KEY, bot TEXT NOT NULL);
CREATE TABLE optional_tables (installation TEXT NOT NULL REFERENCES installations (id),
  table_name TEXT NOT NULL, PRIMARY KEY (installation, table_name));
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE FUNCTION installations_of_bot() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT i.id FROM installations i WHERE i.bot = current_setting('app.user_id', true)
$$;
ALTER FUNCTION installations_of_bot() OWNER TO authz_owner;
GRANT SELECT ON installations TO authz_owner;
ALTER TABLE optional_tables ENABLE ROW LEVEL SECURITY;
CREATE POLICY optional_read ON optional_tables FOR SELECT USING (
  installation = ANY (ARRAY(SELECT installations_of_bot())));
";
    let outputs = translator(ConfidenceLevel::B, &["installations_of_bot"])
        .translate(&db_of(sql))
        .expect("the schema should plan")
        .outputs()
        .expect("every clause should translate");
    let dsl = outputs.model();
    assert_eq!(
        relation_definition(&dsl, "optional_tables", "can_select").as_deref(),
        Some("installations_of_bot from installations")
    );
    let bots: Vec<&str> = outputs
        .tuple_queries()
        .iter()
        .map(|query| query.sql.as_str())
        .filter(|sql| sql.contains("FROM \"public\".\"installations\"") && sql.contains("\"bot\""))
        .collect();
    assert_eq!(bots.len(), 1, "{bots:#?}");
    assert!(
        !bots[0].contains("\nAND ("),
        "every row naming a bot loads: {}",
        bots[0]
    );
}

/// R100's installations, whose `owner` may be a team or a project and references
/// neither, administered through a helper reading it once per level.
pub(crate) const INSTALLATIONS: &str = "
CREATE TABLE installations (id TEXT PRIMARY KEY, owner TEXT NOT NULL);
CREATE TABLE installation_tables (id TEXT PRIMARY KEY,
  installation TEXT NOT NULL REFERENCES installations (id), table_name TEXT NOT NULL);
CREATE FUNCTION authz.installations_administered() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT i.id FROM public.installations i WHERE i.owner IN (SELECT authz.teams_with('admin'))
  UNION
  SELECT i.id FROM public.installations i WHERE i.owner IN (SELECT authz.projects_with('admin'))
$$;
ALTER FUNCTION authz.installations_administered() OWNER TO authz_owner;
GRANT SELECT ON installations TO authz_owner;
ALTER TABLE installations ENABLE ROW LEVEL SECURITY;
CREATE POLICY installations_read ON installations FOR SELECT USING (
  owner = ANY (ARRAY(SELECT authz.teams_with('admin')))
  OR owner = ANY (ARRAY(SELECT authz.projects_with('admin'))));
ALTER TABLE installation_tables ENABLE ROW LEVEL SECURITY;
CREATE POLICY installation_tables_read ON installation_tables FOR SELECT USING (
  installation = ANY (ARRAY(SELECT authz.installations_administered())));
";

/// Every helper the installations read.
pub(crate) const INSTALLATION_HELPERS: &[&str] = &[
    "authz.projects_with",
    "authz.teams_with",
    "authz.installations_administered",
];

/// A column referencing nothing names the rows of the table the set it is compared
/// with covers, so each level it is compared with is one parent of the row.
#[test]
fn a_column_with_no_foreign_key_is_a_parent_of_each_level_it_is_compared_with() {
    let dsl = model(
        &format!("{LEVELS}{OWNER_READS}{INSTALLATIONS}"),
        INSTALLATION_HELPERS,
    );
    let definition = |type_name: &str, relation: &str| {
        relation_definition(&dsl, type_name, relation).unwrap_or_else(|| panic!("{dsl}"))
    };
    assert_eq!(
        definition("installations", "can_select"),
        "teams_with_admin from teams or projects_with_admin from projects"
    );
    assert_eq!(
        definition("installations", "installations_administered"),
        "teams_with_admin from teams or projects_with_admin from projects"
    );
    assert_eq!(definition("installations", "teams"), "[teams]");
    assert_eq!(definition("installations", "projects"), "[projects]");
    assert_eq!(
        definition("installation_tables", "can_select"),
        "installations_administered from installations"
    );
}
