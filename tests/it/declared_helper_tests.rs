//! A column compared with the set a declared `SECURITY DEFINER` helper returns becomes
//! the grants the helper's body reads, `role from parent` through each parent arm.

use core::fmt::Write as _;

use rls2fga::classifier::patterns::{
    ClassifiedExpr, GrantRows, HelperSetArm, PatternClass, UnclassifiedExpr,
};
use rls2fga::generator::tuple_generator::SkippedTuples;
use rls2fga::parser::sql_parser::SessionSetting;
use rls2fga::translator::{Translator, TranslatorBuilder};
use rls2fga::types::{AttributeLiteral, AttributePredicate, AttributeTest, ConfidenceLevel};
use rls2fga::types::{ColumnName, RequestPredicate, RowDecision, TranslationNote};
use sqlparser::ast::DataType;

use crate::support::deployment::{
    caller, delimited_set, deployment, scalar, typed_caller, typed_scalar,
};
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
pub(crate) fn translator(min_confidence: ConfidenceLevel, helpers: &[&str]) -> Translator {
    TranslatorBuilder::new(deployment([caller("app.user_id"), scalar("app.tenant")]))
        .with_min_confidence(min_confidence)
        .with_declared_helpers(helpers)
        .build()
}

pub(crate) fn model(sql: &str, helpers: &[&str]) -> String {
    translator(ConfidenceLevel::B, helpers)
        .translate(&db_of(sql))
        .expect("the schema should plan")
        .outputs()
        .expect("every clause should translate")
        .model()
        .clone()
}

/// The `USING` classification of the policy named `policy`.
pub(crate) fn using_of(sql: &str, helpers: &[&str], policy: &str) -> ClassifiedExpr {
    translator(ConfidenceLevel::B, helpers)
        .classify(&db_of(sql))
        .into_iter()
        .find(|classified| classified.name() == policy)
        .unwrap_or_else(|| panic!("{policy} should classify"))
        .using_classification()
        .expect("USING should classify")
        .clone()
}

pub(crate) fn refusal_of(sql: &str, helpers: &[&str], policy: &str) -> String {
    let classified = using_of(sql, helpers, policy);
    assert_eq!(classified.confidence, ConfidenceLevel::D, "{classified:?}");
    match classified.pattern {
        PatternClass::Unknown(UnclassifiedExpr { reason, .. }) => reason,
        other => panic!("{policy} should be refused, got {other:?}"),
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
        Some("projects_with_read and acting_app_user from request_gate")
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
    assert_eq!(
        spelled("project_id IN (SELECT p.id FROM authz.projects_with('read') p(id))"),
        array
    );
    assert_eq!(
        spelled("project_id IN (SELECT id FROM authz.projects_with('read') AS p (id))"),
        array
    );
    assert_eq!(
        spelled("project_id = ANY (ARRAY(SELECT p FROM authz.projects_with('read') p))"),
        array
    );
    assert_eq!(
        spelled("project_id IN (SELECT projects_with FROM authz.projects_with('read'))"),
        array
    );
}

/// A call in `FROM` is the set it returns, so the helper's own table is no rescan of the
/// guarded one, and the call is refused by name only until it is declared.
#[test]
fn a_call_in_from_on_the_level_itself_is_the_declared_set() {
    let sql = format!(
        "{LEVELS}{OWNER_READS}
         ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
         CREATE POLICY projects_read ON projects FOR SELECT USING (
           id IN (SELECT p.id FROM authz.projects_with('read') p(id)));"
    );
    assert_eq!(
        relation_definition(&model(&sql, BOTH), "projects", "can_select").as_deref(),
        Some("projects_with_read and acting_app_user from request_gate")
    );
    let reason = refusal_of(&sql, &[], "projects_read");
    assert!(reason.contains("'authz.projects_with'"), "{reason}");
    assert!(!reason.contains("recursion"), "{reason}");
}

/// A subquery over the call that projects or keeps anything but the rows it returns, or
/// that `PostgreSQL` refuses outright, is not read as the helper's set.
#[test]
fn a_call_in_from_projecting_or_filtering_its_rows_is_not_the_declared_set() {
    for subquery in [
        "SELECT lower(p) FROM authz.projects_with('read') p",
        "SELECT 'read' FROM authz.projects_with('read') p",
        "SELECT p FROM authz.projects_with('read') p WHERE p <> 'archived'",
        "SELECT p FROM authz.projects_with('read') p LIMIT 1",
        "SELECT p FROM authz.projects_with('read') p, projects",
        "SELECT p.id FROM authz.projects_with('read') WITH ORDINALITY p(id, n) WHERE p.n = 1",
        "SELECT p, p FROM authz.projects_with('read') p",
        "SELECT p.id FROM authz.projects_with('read') p(id, n)",
        "SELECT public.p.id FROM authz.projects_with('read') p(id)",
    ] {
        let sql = format!(
            "{LEVELS}{OWNER_READS}
             ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
             CREATE POLICY orders_read ON orders FOR SELECT USING (
               project_id IN ({subquery}));"
        );
        let classified = using_of(&sql, BOTH, "orders_read");
        assert!(
            matches!(classified.pattern, PatternClass::Unknown(_)),
            "{subquery}: {classified:?}"
        );
    }
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
        reason.contains("'public.projects'") && reason.contains("'public.teams'"),
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
                predicates: vec![AttributePredicate {
                    column: ColumnName::from_stored("role"),
                    test: AttributeTest::In(vec![
                        AttributeLiteral::Text("admin".into()),
                        AttributeLiteral::Text("write".into()),
                    ]),
                }],
            },
            "{case}"
        );
    }
}

/// `pg_dump` writes the role check as `= ANY (ARRAY[...])`, every literal cast to `text`,
/// and the policy with the literal cast and the call aliased.
#[test]
fn the_dumped_spelling_reads_as_the_written_one() {
    let translate = |sql: &str| {
        translator(ConfidenceLevel::B, BOTH)
            .translate(&db_of(sql))
            .expect("the schema should plan")
            .outputs()
            .expect("every clause should translate")
    };
    let written_sql = format!("{LEVELS}{OWNER_READS}{ORDERS}");
    let written = translate(&written_sql);
    let dumped = written_sql
        .replace(
            "CHECK (role IN ('read', 'write', 'admin'))",
            // `read` twice, which the closed domain holds once.
            "CONSTRAINT role_check CHECK ((role = ANY (ARRAY['read'::text, 'write'::text, 'admin'::text, 'read'::text])))",
        )
        .replace(
            "project_id = ANY (ARRAY(SELECT authz.projects_with('read')))",
            "(project_id = ANY (ARRAY( SELECT authz.projects_with('read'::text) AS projects_with)))",
        )
        .replace("authz.projects_with", "\"authz\".\"projects_with\"")
        .replace("authz.teams_with", "\"authz\".\"teams_with\"");
    let dumped = translate(&dumped);
    assert_eq!(dumped.model(), written.model());
    assert_eq!(dumped.report(), written.report());
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
            "column 'team_id' names rows of 'public.teams'",
        ),
        (
            "projects_read",
            "team_id = ANY (ARRAY(SELECT authz.tenant_teams()))",
            "reads setting `app.tenant` as the caller, which it is not",
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
    for ((orders, using), expected) in [
        (
            (
                keyed,
                "project_id = ANY (ARRAY(SELECT authz.projects_as('owner')))",
            ),
            "no_access and acting_app_user from request_gate",
        ),
        (
            (
                unkeyed,
                "project_id = ANY (ARRAY(SELECT authz.projects_as('read')))",
            ),
            "no_access",
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
            Some(expected),
            "`{using}`: {dsl}"
        );
    }
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
        Some("installations_of_bot from installations and acting_app_user from request_gate")
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
        "(teams_with_admin from teams or projects_with_admin from projects) \
         and acting_app_user from request_gate"
    );
    assert_eq!(
        definition("installations", "installations_administered"),
        "teams_with_admin from teams or projects_with_admin from projects"
    );
    assert_eq!(definition("installations", "teams"), "[teams]");
    assert_eq!(definition("installations", "projects"), "[projects]");
    assert_eq!(
        definition("installation_tables", "can_select"),
        "installations_administered from installations and acting_app_user from request_gate"
    );
}

/// Share links the request presents and the installation it acts through, each resolved
/// by a declared helper.
pub(crate) const REQUEST_VALUES: &str = "
CREATE TABLE share_links (id TEXT PRIMARY KEY, revoked BOOLEAN NOT NULL DEFAULT FALSE);
CREATE TABLE installation_permissions (
  installation_id TEXT NOT NULL,
  table_name TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('select', 'insert', 'update', 'delete')),
  PRIMARY KEY (installation_id, table_name, action)
);
GRANT SELECT ON share_links, installation_permissions TO authz_owner;
CREATE FUNCTION authz.presented_links() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT l.id FROM public.share_links l
  WHERE l.id = ANY (string_to_array(current_setting('app.link_ids', true), ',')) AND l.revoked = FALSE
$$;
CREATE FUNCTION authz.installations_allowing(target TEXT, command TEXT) RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT ip.installation_id FROM public.installation_permissions ip
  WHERE ip.table_name = target AND ip.action = command
$$;
ALTER FUNCTION authz.presented_links() OWNER TO authz_owner;
ALTER FUNCTION authz.installations_allowing(TEXT, TEXT) OWNER TO authz_owner;
CREATE TABLE docs (id TEXT PRIMARY KEY, link_id TEXT NOT NULL REFERENCES share_links (id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_by_link ON docs FOR SELECT
  USING (link_id = ANY (ARRAY(SELECT authz.presented_links())));
CREATE POLICY docs_installation ON docs AS RESTRICTIVE FOR SELECT
  USING (current_setting('app.installation_id', true) = ''
         OR current_setting('app.installation_id', true) IN (SELECT authz.installations_allowing('docs', 'select')));
";

/// The helpers [`REQUEST_VALUES`] reads.
pub(crate) const REQUEST_HELPERS: &[&str] =
    &["authz.presented_links", "authz.installations_allowing"];

/// A share link set and an installation scalar the request carries, beside the caller.
fn request_translator() -> Translator {
    TranslatorBuilder::new(deployment([
        caller("app.user_id"),
        scalar("app.installation_id"),
        delimited_set("app.link_ids", ","),
    ]))
    .with_min_confidence(ConfidenceLevel::B)
    .with_declared_helpers(REQUEST_HELPERS)
    .build()
}

/// A helper arm comparing its column with a request set, and a request scalar compared
/// with the rows a helper returns for literal arguments, both read as request values.
#[test]
fn request_values_behind_declared_helpers_translate() {
    let db = db_of(&format!("{LEVELS}{OWNER_READS}{REQUEST_VALUES}"));
    let classified = request_translator().classify(&db);
    for policy in ["docs_by_link", "docs_installation"] {
        let using = classified
            .iter()
            .find(|classified| classified.name() == policy)
            .unwrap_or_else(|| panic!("{policy} should classify"))
            .using_classification()
            .expect("USING should classify");
        assert_eq!(using.confidence, ConfidenceLevel::A, "{policy}: {using:?}");
    }
    // An `OR` reports its parts' count, so a policy of P27 alone shows the pattern.
    let alone = db_of(&format!(
        "{LEVELS}{OWNER_READS}{REQUEST_VALUES}
         CREATE POLICY docs_installed ON docs AS RESTRICTIVE FOR SELECT
           USING (current_setting('app.installation_id', true)
                  IN (SELECT authz.installations_allowing('docs', 'select')));"
    ));
    let report = request_translator()
        .translate(&alone)
        .expect("the schema should plan")
        .outputs()
        .expect("every clause should translate")
        .report();
    assert!(
        report.contains(
            "P27 (caller value app_installation_id in \
             authz.installations_allowing('docs', 'select'))"
        ),
        "{report}"
    );
}

/// Documents every request may read, capped by an installation the request may leave
/// unset, which the cap then lets through.
pub(crate) const ABSENT_INSTALLATION: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE docs (id UUID PRIMARY KEY);
CREATE TABLE installation_permissions (
  installation_id UUID NOT NULL,
  table_name TEXT NOT NULL,
  action TEXT NOT NULL,
  PRIMARY KEY (installation_id, table_name, action)
);
GRANT SELECT ON installation_permissions TO authz_owner;
CREATE FUNCTION authz.installations_allowing(target TEXT, command TEXT) RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT ip.installation_id FROM public.installation_permissions ip
  WHERE ip.table_name = target AND ip.action = command
$$;
ALTER FUNCTION authz.installations_allowing(TEXT, TEXT) OWNER TO authz_owner;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_read ON docs FOR SELECT USING (TRUE);
CREATE POLICY docs_installation ON docs AS RESTRICTIVE FOR SELECT
  USING ((SELECT NULLIF(current_setting('app.installation_id', true), '')::uuid) IS NULL
    OR (SELECT NULLIF(current_setting('app.installation_id', true), '')::uuid)
       IN (SELECT authz.installations_allowing('docs', 'select')));
";

/// The caller, and an installation the request carries or leaves unset.
fn absent_installation_translator(installation: SessionSetting) -> Translator {
    TranslatorBuilder::new(deployment([caller("app.user_id"), installation]))
        .with_min_confidence(ConfidenceLevel::B)
        .with_declared_helpers(["authz.installations_allowing"])
        .build()
}

/// `NULLIF(<read>, '')` of an installation the request may leave unset reads as the
/// request value, and testing it for `NULL` as the request leaving it out, so the cap
/// becomes an `or` of the request omitting the installation and the helper allowing it.
#[test]
fn an_installation_the_request_may_leave_unset_caps_through_its_absence() {
    let translator = absent_installation_translator(
        typed_scalar("app.installation_id", DataType::Uuid).may_be_unset(),
    );
    let outputs = translator
        .translate(&db_of(ABSENT_INSTALLATION))
        .expect("the schema should plan")
        .outputs()
        .expect("every clause should translate");
    let model = outputs.model();
    let select = relation_definition(&model, "docs", "can_select").expect("docs is readable");
    assert!(
        select.contains(" or app_installation_id_absent_")
            && select.contains("app_installation_id_in_installations_allo"),
        "{model}"
    );
    assert!(
        model.contains("!(\"app_installation_id\" in settings)"),
        "{model}"
    );
    // An `OR` reports its parts' count, so each half alone shows its pattern.
    for (using, part) in [
        (
            "(SELECT NULLIF(current_setting('app.installation_id', true), '')::uuid) IS NOT NULL",
            "P28 (caller value app_installation_id carried)",
        ),
        (
            "NULLIF(current_setting('app.installation_id', true), '')::uuid \
             IN (SELECT authz.installations_allowing('docs', 'select'))",
            "P27 (caller value app_installation_id in \
             authz.installations_allowing('docs', 'select'))",
        ),
    ] {
        let alone = db_of(&format!(
            "{ABSENT_INSTALLATION}
             CREATE POLICY docs_alone ON docs AS RESTRICTIVE FOR SELECT USING ({using});"
        ));
        let report = translator
            .translate(&alone)
            .expect("the schema should plan")
            .outputs()
            .expect("every clause should translate")
            .report();
        assert!(report.contains(part), "{report}");
    }
}

/// The relation report states an absence test as the request omitting the key, and its
/// negation as the request carrying it, which a consumer decides from the check context
/// alone.
#[test]
fn an_absence_test_reports_the_key_the_request_omits_or_carries() {
    let translator = absent_installation_translator(
        typed_scalar("app.installation_id", DataType::Uuid).may_be_unset(),
    );
    let db = db_of(
        "CREATE TABLE unset_notes (id UUID PRIMARY KEY);
         CREATE TABLE set_notes (id UUID PRIMARY KEY);
         ALTER TABLE unset_notes ENABLE ROW LEVEL SECURITY;
         ALTER TABLE set_notes ENABLE ROW LEVEL SECURITY;
         CREATE POLICY unset_read ON unset_notes FOR SELECT
           USING (NULLIF(current_setting('app.installation_id', true), '') IS NULL);
         CREATE POLICY set_read ON set_notes FOR SELECT
           USING (NULLIF(current_setting('app.installation_id', true), '') IS NOT NULL);",
    );
    let translation = translator.translate(&db).expect("the schema should plan");
    let gate = |table: &str| {
        let decision = translation
            .relations()
            .iter()
            .find(|entry| {
                entry.type_name.as_str() == table && entry.relation.as_str() == "can_select"
            })
            .and_then(|entry| entry.decision.clone())
            .unwrap_or_else(|| panic!("the request decides {table}#can_select"));
        request_predicates(&decision)
    };
    let parameter = "app_installation_id".to_string();
    let acting = RequestPredicate::ActsAs {
        role: "app_user".to_string(),
    };
    assert_eq!(
        gate("unset_notes"),
        [
            RequestPredicate::Omits {
                request_parameter: parameter.clone()
            },
            acting.clone()
        ]
    );
    assert_eq!(
        gate("set_notes"),
        [
            RequestPredicate::Carries {
                request_parameter: parameter
            },
            acting
        ]
    );
}

/// The predicates of every request gate in `decision`.
fn request_predicates(decision: &RowDecision) -> Vec<RequestPredicate> {
    match decision {
        RowDecision::Any(children) | RowDecision::All(children) => {
            children.iter().flat_map(request_predicates).collect()
        }
        RowDecision::Request { predicate, .. } => vec![predicate.clone()],
        _ => Vec::new(),
    }
}

/// An installation every request sets may hold `''`, which `NULLIF` would read as
/// absent, so the cap stays refused, naming why.
#[test]
fn an_installation_every_request_sets_refuses_the_absence_test() {
    let translator =
        absent_installation_translator(typed_scalar("app.installation_id", DataType::Uuid));
    let classified = translator.classify(&db_of(ABSENT_INSTALLATION));
    let using = classified
        .iter()
        .find(|classified| classified.name() == "docs_installation")
        .expect("the cap should classify")
        .using_classification()
        .expect("USING should classify");
    assert_eq!(using.confidence, ConfidenceLevel::D, "{using:?}");
    let shown = format!("{using:?}");
    assert!(
        shown.contains("'app.installation_id' is declared set by every request"),
        "{shown}"
    );
}

/// `NOT` around an absence test is the opposite test, since an absence test is never
/// `NULL`.
#[test]
fn a_negated_absence_test_is_the_opposite_test() {
    let translator = absent_installation_translator(
        typed_scalar("app.installation_id", DataType::Uuid).may_be_unset(),
    );
    for (using, carried) in [
        (
            "NOT (NULLIF(current_setting('app.installation_id', true), '') IS NULL)",
            true,
        ),
        (
            "NOT NOT (NULLIF(current_setting('app.installation_id', true), '') IS NULL)",
            false,
        ),
        (
            "NOT (NULLIF(current_setting('app.installation_id', true), '') IS NOT NULL)",
            false,
        ),
    ] {
        let classified = translator.classify(&db_of(&format!(
            "{ABSENT_INSTALLATION}
             CREATE POLICY docs_negated ON docs AS RESTRICTIVE FOR SELECT USING ({using});"
        )));
        let pattern = &classified
            .iter()
            .find(|classified| classified.name() == "docs_negated")
            .expect("the negation should classify")
            .using_classification()
            .expect("USING should classify")
            .pattern;
        assert!(
            matches!(
                pattern,
                PatternClass::P28RequestValueAbsent(test) if test.negated == carried
            ),
            "`{using}`: {pattern:?}"
        );
    }
}

/// A request value behind a helper falls closed where the rows it reads depend on the
/// request or on the statement time, and so does a grant to everyone kept by the
/// statement time and a caller gate on rows a request's set admits.
#[test]
fn request_values_the_gates_cannot_carry_are_refused() {
    let policy = |using: &str| {
        format!(
            "{LEVELS}{OWNER_READS}{REQUEST_VALUES}
             CREATE TABLE expiring_links (id TEXT PRIMARY KEY, expires_at TIMESTAMPTZ NOT NULL);
             GRANT SELECT ON expiring_links TO authz_owner;
             CREATE FUNCTION authz.live_links() RETURNS SETOF TEXT
             LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
               SELECT e.id FROM public.expiring_links e
               WHERE e.id = ANY (string_to_array(current_setting('app.link_ids', true), ','))
                 AND e.expires_at > now()
             $$;
             CREATE FUNCTION authz.live_ids() RETURNS SETOF TEXT
             LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
               SELECT e.id FROM public.expiring_links e WHERE e.expires_at > now()
             $$;
             CREATE FUNCTION authz.gated_links() RETURNS SETOF TEXT
             LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
               SELECT l.id FROM public.share_links l
               WHERE l.id = ANY (string_to_array(current_setting('app.link_ids', true), ','))
                 AND current_setting('app.user_id', true) <> 'anonymous'
             $$;
             ALTER FUNCTION authz.live_links() OWNER TO authz_owner;
             ALTER FUNCTION authz.live_ids() OWNER TO authz_owner;
             ALTER FUNCTION authz.gated_links() OWNER TO authz_owner;
             CREATE FUNCTION authz.allowing_twice(target TEXT) RETURNS SETOF TEXT
             LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
               SELECT ip.installation_id FROM public.installation_permissions ip
               WHERE ip.table_name = target
             $$;
             CREATE FUNCTION authz.allowing_twice(target INT) RETURNS SETOF TEXT
             LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
               SELECT ip.installation_id FROM public.installation_permissions ip
             $$;
             ALTER FUNCTION authz.allowing_twice(TEXT) OWNER TO authz_owner;
             ALTER FUNCTION authz.allowing_twice(INT) OWNER TO authz_owner;
             CREATE TABLE notes (id TEXT PRIMARY KEY,
               link_id TEXT NOT NULL REFERENCES share_links (id),
               live_id TEXT NOT NULL REFERENCES expiring_links (id),
               project_id TEXT REFERENCES projects (id));
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
             CREATE POLICY notes_read ON notes FOR SELECT USING ({using});"
        )
    };
    let helpers = [
        "authz.presented_links",
        "authz.installations_allowing",
        "authz.live_links",
        "authz.live_ids",
        "authz.gated_links",
        "authz.allowing_twice",
    ];
    let translator = TranslatorBuilder::new(deployment([
        caller("app.user_id"),
        scalar("app.installation_id"),
        delimited_set("app.link_ids", ","),
    ]))
    .with_min_confidence(ConfidenceLevel::B)
    .with_declared_helpers(helpers)
    .build();
    let cases = [
        (
            "current_setting('app.installation_id', true) IN (SELECT authz.presented_links())",
            "is compared with the request's value 'app.installation_id'",
        ),
        (
            "current_setting('app.installation_id', true) IN (SELECT authz.live_ids())",
            "keeps the rows of 'public.expiring_links' it compares with a request value by the \
             statement time",
        ),
        (
            "live_id = ANY (ARRAY(SELECT authz.live_links()))",
            "keeps the rows of 'public.expiring_links' it compares with a request value by the \
             statement time",
        ),
        (
            "live_id = ANY (ARRAY(SELECT authz.live_ids()))",
            "keeps the rows of 'public.expiring_links' naming a set of grantees or everyone by \
             the statement time",
        ),
        (
            "link_id = ANY (ARRAY(SELECT authz.gated_links()))",
            "excludes callers from rows a set the request carries admits",
        ),
        (
            "current_setting('app.installation_id', true) IN (SELECT authz.gated_links())",
            "is compared with the request's value 'app.installation_id'",
        ),
        (
            "NOT (current_setting('app.installation_id', true) \
             IN (SELECT authz.installations_allowing('docs', 'select')))",
            "NOT applied to declared caller value among a declared helper's values",
        ),
        (
            "current_setting('app.installation_id', true) IN (SELECT authz.allowing_twice('docs'))",
            "more than one declaration of 'authz.allowing_twice' takes this call's arguments",
        ),
    ];
    for (using, reason) in cases {
        let classified = translator
            .classify(&db_of(&policy(using)))
            .into_iter()
            .find(|classified| classified.name() == "notes_read")
            .expect("notes_read should classify")
            .using_classification()
            .expect("USING should classify")
            .clone();
        assert_eq!(classified.confidence, ConfidenceLevel::D, "`{using}`");
        match classified.pattern {
            PatternClass::Unknown(UnclassifiedExpr {
                reason: refused, ..
            }) => {
                assert!(refused.contains(reason), "`{using}`: {refused}");
            }
            other => panic!("`{using}` should be refused, got {other:?}"),
        }
    }
}

/// A helper reading rows with no identity, or a guarded table with none, loads no share
/// tuple and no gate link, so the gate it needs is noted as skipped and admits nobody.
#[test]
fn request_values_over_rows_without_identity_are_skipped() {
    let sql = format!(
        "{LEVELS}{OWNER_READS}{REQUEST_VALUES}
         CREATE TABLE loose_permissions (installation_id TEXT NOT NULL);
         CREATE TABLE link_tokens (link_id TEXT NOT NULL REFERENCES share_links (id),
           token TEXT NOT NULL);
         GRANT SELECT ON loose_permissions, link_tokens TO authz_owner;
         CREATE FUNCTION authz.loose_installations() RETURNS SETOF TEXT
         LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
           SELECT lp.installation_id FROM public.loose_permissions lp
         $$;
         CREATE FUNCTION authz.tokened_links() RETURNS SETOF TEXT
         LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
           SELECT t.link_id FROM public.link_tokens t
           WHERE t.token = ANY (string_to_array(current_setting('app.link_ids', true), ','))
         $$;
         ALTER FUNCTION authz.loose_installations() OWNER TO authz_owner;
         ALTER FUNCTION authz.tokened_links() OWNER TO authz_owner;
         CREATE TABLE notes (id TEXT PRIMARY KEY, link_id TEXT NOT NULL REFERENCES share_links (id));
         CREATE TABLE loose_notes (body TEXT);
         ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
         ALTER TABLE loose_notes ENABLE ROW LEVEL SECURITY;
         CREATE POLICY notes_by_token ON notes FOR SELECT
           USING (link_id = ANY (ARRAY(SELECT authz.tokened_links())));
         CREATE POLICY notes_installation ON notes AS RESTRICTIVE FOR SELECT
           USING (current_setting('app.installation_id', true)
                  IN (SELECT authz.loose_installations()));
         CREATE POLICY loose_notes_installation ON loose_notes FOR SELECT
           USING (current_setting('app.installation_id', true)
                  IN (SELECT authz.installations_allowing('loose_notes', 'select')));"
    );
    let mut helpers = REQUEST_HELPERS.to_vec();
    helpers.extend(["authz.loose_installations", "authz.tokened_links"]);
    let outputs = TranslatorBuilder::new(deployment([
        caller("app.user_id"),
        scalar("app.installation_id"),
        delimited_set("app.link_ids", ","),
    ]))
    .with_min_confidence(ConfidenceLevel::B)
    .with_declared_helpers(helpers)
    .build()
    .translate(&db_of(&sql))
    .expect("the schema should plan")
    .outputs_accepting_gaps();
    let skipped: Vec<(String, String)> = outputs
        .tuple_queries()
        .iter()
        .filter_map(|query| match &query.skipped {
            Some(SkippedTuples::NoObjectIdentifier { table, what, .. }) => {
                Some((table.to_string(), what.clone()))
            }
            _ => None,
        })
        .collect();
    for expected in [
        ("public.link_tokens", "request value shares"),
        ("public.loose_permissions", "request value shares"),
        ("public.loose_notes", "request gate links"),
    ] {
        assert!(
            skipped
                .iter()
                .any(|(table, what)| (table.as_str(), what.as_str()) == expected),
            "{expected:?} should be skipped: {skipped:?}"
        );
    }
    let model = outputs.model();
    for table in ["notes", "loose_notes"] {
        let can_select = relation_definition(&model, table, "can_select")
            .unwrap_or_else(|| panic!("{table} should define can_select:\n{model}"));
        assert!(
            can_select.contains("no_access"),
            "{table} should admit nobody: {can_select}"
        );
    }
}

/// connetto's group tree under the teams, with a helper granting a group and every group
/// below it through a recursive walk down `parent_id`.
pub(crate) const GROUPS: &str = "
CREATE TABLE groups (id TEXT PRIMARY KEY, parent_id TEXT REFERENCES groups (id),
  team_id TEXT REFERENCES teams (id));
CREATE TABLE group_grants (group_id TEXT NOT NULL REFERENCES groups (id), principal_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('read', 'write')), PRIMARY KEY (group_id, principal_id));
CREATE TABLE docs (id TEXT PRIMARY KEY, group_id TEXT NOT NULL REFERENCES groups (id), title TEXT);
CREATE FUNCTION authz.groups_with(min_role TEXT) RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  WITH RECURSIVE reached (id) AS (
    SELECT g.group_id FROM public.group_grants g
    WHERE g.principal_id = current_setting('app.user_id', true)
      AND (g.role = 'write' OR min_role = 'read')
    UNION
    SELECT child.id FROM public.groups child JOIN reached ON child.parent_id = reached.id
  )
  SELECT id FROM reached
$$;
ALTER FUNCTION authz.groups_with(TEXT) OWNER TO authz_owner;
GRANT SELECT ON groups, group_grants TO authz_owner;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_read ON docs FOR SELECT USING (
  group_id = ANY (ARRAY(SELECT authz.groups_with('read'))));
CREATE POLICY docs_update ON docs FOR UPDATE
  USING (group_id = ANY (ARRAY(SELECT authz.groups_with('write'))))
  WITH CHECK (group_id = ANY (ARRAY(SELECT authz.groups_with('write'))));
";

/// Every row below a group the call returns holds it too, so the call's relation holds
/// whoever holds it on the group's parent.
#[test]
fn a_walk_down_a_tree_reads_the_call_from_each_parent() {
    let dsl = model(
        &format!("{LEVELS}{OWNER_READS}{GROUPS}"),
        &["authz.groups_with"],
    );
    let definition = |type_name: &str, relation: &str| {
        relation_definition(&dsl, type_name, relation).unwrap_or_else(|| panic!("{dsl}"))
    };
    assert_eq!(definition("groups", "groups"), "[groups]");
    assert_eq!(
        definition("groups", "groups_with_read"),
        "read or write or groups_with_read from groups"
    );
    assert_eq!(
        definition("groups", "groups_with_write"),
        "write or groups_with_write from groups"
    );
    assert_eq!(
        definition("docs", "can_select"),
        "groups_with_read from groups and acting_app_user from request_gate"
    );
}

/// The rows a parent arm returns are walked down like the caller's grants.
#[test]
fn a_walk_composes_with_a_parent_arm() {
    let sql = format!(
        "{LEVELS}{OWNER_READS}{GROUPS}
         CREATE FUNCTION authz.groups_reached(min_role TEXT) RETURNS SETOF TEXT
         LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
           WITH RECURSIVE reached (id) AS (
             SELECT g.group_id FROM public.group_grants g
             WHERE g.principal_id = current_setting('app.user_id', true)
               AND (g.role = 'write' OR min_role = 'read')
             UNION
             SELECT g.id FROM public.groups g WHERE g.team_id IN (SELECT authz.teams_with(min_role))
             UNION
             SELECT child.id FROM public.groups child JOIN reached ON child.parent_id = reached.id
           )
           SELECT id FROM reached
         $$;
         ALTER FUNCTION authz.groups_reached(TEXT) OWNER TO authz_owner;
         ALTER TABLE groups ENABLE ROW LEVEL SECURITY;
         CREATE POLICY groups_read ON groups FOR SELECT USING (
           id = ANY (ARRAY(SELECT authz.groups_reached('read'))));"
    );
    let dsl = model(
        &sql,
        &[
            "authz.groups_reached",
            "authz.groups_with",
            "authz.teams_with",
        ],
    );
    assert_eq!(
        relation_definition(&dsl, "groups", "groups_reached_read").as_deref(),
        Some("read or write or teams_with_read from teams or groups_reached_read from groups"),
        "{dsl}"
    );
}

/// `OpenFGA` resolves a walk only so deep, and the schema cannot say how deep the tree
/// goes, so each walk the model resolves is noted once, however many clauses call it.
#[test]
fn each_walk_is_noted_once_with_the_depth_openfga_resolves() {
    let notes = translator(ConfidenceLevel::B, &["authz.groups_with"])
        .translate(&db_of(&format!("{LEVELS}{OWNER_READS}{GROUPS}")))
        .expect("the schema should plan")
        .outputs()
        .expect("every clause should translate")
        .notes()
        .to_vec();
    let walks: Vec<(String, String, String, String)> = notes
        .iter()
        .filter_map(|note| match note {
            TranslationNote::HelperWalkDepth {
                function,
                table,
                column,
                relation,
            } => Some((
                function.clone(),
                table.to_string(),
                column.to_string(),
                relation.to_string(),
            )),
            _ => None,
        })
        .collect();
    let walk = |relation: &str| {
        (
            "authz.groups_with".to_string(),
            "public.groups".to_string(),
            "parent_id".to_string(),
            relation.to_string(),
        )
    };
    assert_eq!(
        walks,
        [walk("groups_with_read"), walk("groups_with_write")],
        "{notes:#?}"
    );
}

/// Projects every caller sees, every caller but `anonymous` sees, or their members see
/// but `anonymous`.
pub(crate) const AUDIENCES: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE projects (id TEXT PRIMARY KEY,
  visibility TEXT NOT NULL CHECK (visibility IN ('public', 'signed_in', 'private')));
CREATE TABLE project_members (project_id TEXT NOT NULL REFERENCES projects (id),
  user_id TEXT NOT NULL, PRIMARY KEY (project_id, user_id));
GRANT SELECT ON projects, project_members TO authz_owner;
CREATE FUNCTION authz.projects_visible() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT p.id FROM public.projects p WHERE p.visibility = 'public'
  UNION
  SELECT p.id FROM public.projects p
  WHERE p.visibility = 'signed_in' AND current_setting('app.user_id', true) <> 'anonymous'
  UNION
  SELECT m.project_id FROM public.project_members m
  WHERE m.user_id = current_setting('app.user_id', true)
    AND current_setting('app.user_id', true) <> 'anonymous'
$$;
ALTER FUNCTION authz.projects_visible() OWNER TO authz_owner;
CREATE TABLE docs (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects (id), title TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_read ON docs FOR SELECT USING (
  project_id = ANY (ARRAY(SELECT authz.projects_visible())));
";

/// The audience helper declared.
pub(crate) const AUDIENCE_HELPERS: &[&str] = &["authz.projects_visible"];

/// An arm keeping its rows for every caller grants them to `user:*`, and one gated on
/// the caller being someone other than a constant grants them to every user but that
/// one.
#[test]
fn an_audience_arm_grants_every_caller_but_the_ones_its_gate_excludes() {
    let dsl = model(AUDIENCES, AUDIENCE_HELPERS);
    let definition = |relation: &str| {
        relation_definition(&dsl, "projects", relation).unwrap_or_else(|| panic!("{dsl}"))
    };
    assert_eq!(definition("public"), "[user:*]");
    assert_eq!(definition("signed_in_everyone"), "[user:*]");
    assert_eq!(definition("signed_in_excluded"), "[user]");
    let visible = definition("projects_visible");
    let arms: Vec<&str> = visible.split(" or ").collect();
    assert!(arms.contains(&"public"), "{dsl}");
    assert!(
        arms.contains(&"(signed_in_everyone but not signed_in_excluded)"),
        "{dsl}"
    );
    // No check sends an empty caller, so `<> ''` excludes nobody.
    let ungated = model(
        &AUDIENCES.replace("<> 'anonymous'", "<> ''"),
        AUDIENCE_HELPERS,
    );
    assert_eq!(
        relation_definition(&ungated, "projects", "signed_in").as_deref(),
        Some("[user:*]"),
        "{ungated}"
    );
}

/// The excluded caller is loaded on the rows it is excluded from, and a gated arm naming
/// the caller loads no row naming the excluded one.
#[test]
fn a_caller_gate_loads_the_constant_it_excludes() {
    let outputs = translator(ConfidenceLevel::B, AUDIENCE_HELPERS)
        .translate(&db_of(AUDIENCES))
        .expect("the schema should plan")
        .outputs()
        .expect("every clause should translate");
    let queries: Vec<&str> = outputs
        .tuple_queries()
        .iter()
        .map(|query| query.sql.as_str())
        .collect();
    let reading = |needles: &[&str]| -> usize {
        queries
            .iter()
            .filter(|sql| needles.iter().all(|needle| sql.contains(needle)))
            .count()
    };
    assert_eq!(
        reading(&[
            "'signed_in_excluded' AS relation",
            "'user:anonymous' AS subject",
            "\"visibility\" = 'signed_in'"
        ]),
        1,
        "{queries:#?}"
    );
    assert_eq!(
        reading(&[
            "FROM \"public\".\"project_members\"",
            "\"user_id\" <> 'anonymous'"
        ]),
        1,
        "{queries:#?}"
    );
}

/// A gate on a caller the deployment lets go unset names a request no subject spells
/// apart from a caller's, so an arm granting its audience is refused.
#[test]
fn a_gate_on_a_caller_that_may_be_unset_is_refused() {
    let translator = TranslatorBuilder::new(deployment([caller("app.user_id").may_be_unset()]))
        .with_min_confidence(ConfidenceLevel::B)
        .with_declared_helpers(AUDIENCE_HELPERS)
        .build();
    let reason = audience_refusal(&translator, AUDIENCES);
    assert!(reason.contains("app.user_id"), "{reason}");
}

/// The request's grantees, one `grantee_id` per grant naming a user, an organization's
/// active members, a team with the teams above it, or an audience.
pub(crate) const GRANTEES: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE grantees (id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('user', 'team', 'organization', 'everyone', 'signed_in')));
CREATE TABLE organizations (id TEXT PRIMARY KEY REFERENCES grantees (id));
CREATE TABLE memberships (organization_id TEXT NOT NULL REFERENCES organizations (id),
  user_id TEXT NOT NULL REFERENCES grantees (id),
  state TEXT NOT NULL CHECK (state IN ('active', 'deactivated')),
  PRIMARY KEY (organization_id, user_id));
CREATE TABLE teams (id TEXT PRIMARY KEY REFERENCES grantees (id), parent_id TEXT REFERENCES teams (id));
CREATE TABLE team_members (team_id TEXT NOT NULL REFERENCES teams (id),
  user_id TEXT NOT NULL REFERENCES grantees (id), PRIMARY KEY (team_id, user_id));
CREATE TABLE projects (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations (id));
CREATE TABLE project_grants (project_id TEXT NOT NULL REFERENCES projects (id),
  grantee_id TEXT NOT NULL REFERENCES grantees (id), PRIMARY KEY (project_id, grantee_id));
GRANT SELECT ON grantees, memberships, teams, team_members, project_grants TO authz_owner;
CREATE FUNCTION authz.caller_grantees() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  WITH RECURSIVE reached (id) AS (
    SELECT g.id FROM public.grantees g WHERE g.id = current_setting('app.user_id', true)
    UNION
    SELECT g.id FROM public.grantees g WHERE g.kind = 'everyone'
    UNION
    SELECT g.id FROM public.grantees g WHERE g.kind = 'signed_in' AND current_setting('app.user_id', true) <> ''
    UNION
    SELECT m.organization_id FROM public.memberships m
    WHERE m.user_id = current_setting('app.user_id', true) AND m.state = 'active'
    UNION
    SELECT tm.team_id FROM public.team_members tm WHERE tm.user_id = current_setting('app.user_id', true)
    UNION
    SELECT t.parent_id FROM public.teams t JOIN reached ON t.id = reached.id
  ) SELECT id FROM reached
$$;
CREATE FUNCTION authz.projects_granted() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT pg.project_id FROM public.project_grants pg WHERE pg.grantee_id IN (SELECT authz.caller_grantees())
$$;
ALTER FUNCTION authz.caller_grantees() OWNER TO authz_owner;
ALTER FUNCTION authz.projects_granted() OWNER TO authz_owner;
GRANT EXECUTE ON FUNCTION authz.caller_grantees() TO authz_owner;
CREATE TABLE docs (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects (id), title TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_read ON docs FOR SELECT USING (
  project_id = ANY (ARRAY(SELECT authz.projects_granted())));
";

/// Both grantee helpers declared.
pub(crate) const GRANTEE_HELPERS: &[&str] = &["authz.caller_grantees", "authz.projects_granted"];

/// A grant naming one of the caller's grantees holds whoever the set holds on that
/// grantee, every arm of the set and the walk up the teams on the grantees' own type.
#[test]
fn a_grant_naming_a_set_of_grantees_holds_whoever_the_set_holds_on_it() {
    let dsl = model(GRANTEES, GRANTEE_HELPERS);
    let definition = |type_name: &str, relation: &str| {
        relation_definition(&dsl, type_name, relation).unwrap_or_else(|| panic!("{dsl}"))
    };
    assert_eq!(
        definition("projects", "project_grants"),
        "[grantees#caller_grantees]"
    );
    assert_eq!(definition("projects", "projects_granted"), "project_grants");
    let caller_grantees = definition("grantees", "caller_grantees");
    let arms: Vec<&str> = caller_grantees.split(" or ").collect();
    assert_eq!(arms.last(), Some(&"caller_grantees from child"), "{dsl}");
    assert!(arms.contains(&"active"), "{dsl}");
    assert_eq!(definition("grantees", "active"), "[user]");
    assert_eq!(definition("grantees", "child"), "[grantees]");
    assert_eq!(
        definition("docs", "can_select"),
        "projects_granted from projects and acting_app_user from request_gate"
    );
}

/// Each grant row loads the grantee it names, and the set's arms and the walk up the
/// teams load only from the tables the set's arms read.
#[test]
fn a_grant_row_loads_the_grantee_it_names() {
    let outputs = translator(ConfidenceLevel::B, GRANTEE_HELPERS)
        .translate(&db_of(GRANTEES))
        .expect("the schema should plan")
        .outputs()
        .expect("every clause should translate");
    let queries: Vec<&str> = outputs
        .tuple_queries()
        .iter()
        .map(|query| query.sql.as_str())
        .collect();
    let reading = |needles: &[&str]| -> Vec<&str> {
        queries
            .iter()
            .copied()
            .filter(|sql| needles.iter().all(|needle| sql.contains(needle)))
            .collect()
    };
    assert_eq!(
        reading(&[
            "FROM \"public\".\"project_grants\"",
            "'grantees:' ||",
            "'#caller_grantees'"
        ])
        .len(),
        1,
        "{queries:#?}"
    );
    assert_eq!(
        reading(&["FROM \"public\".\"teams\"", "'child'", "'grantees:' ||"]).len(),
        1,
        "{queries:#?}"
    );
    assert!(
        reading(&["\"public\".\"organizations\""]).is_empty(),
        "no arm reads organizations: {queries:#?}"
    );
}

/// `schema` with `authz.caller_grantees` cut down to the caller and the audiences, so
/// no arm reads a grantee holding another.
pub(crate) fn caller_and_audiences_only(schema: &str) -> String {
    let cut = schema
        .replace(
            "
    UNION
    SELECT m.organization_id FROM public.memberships m
    WHERE m.user_id = current_setting('app.user_id', true) AND m.state = 'active'
    UNION
    SELECT tm.team_id FROM public.team_members tm WHERE tm.user_id = current_setting('app.user_id', true)
    UNION
    SELECT t.parent_id FROM public.teams t JOIN reached ON t.id = reached.id
  ) SELECT id FROM reached",
            "",
        )
        .replace("  WITH RECURSIVE reached (id) AS (\n", "");
    assert!(!cut.contains("reached"), "{cut}");
    cut
}

/// A set whose arms are only the caller and audiences grants each grant row that user
/// or every user, checked against the grantee row it names, with no grantee type.
#[test]
fn a_grant_naming_a_set_of_only_the_caller_and_audiences_grants_users() {
    let schema = caller_and_audiences_only(GRANTEES);
    let dsl = model(&schema, GRANTEE_HELPERS);
    assert_eq!(
        relation_definition(&dsl, "projects", "project_grants").as_deref(),
        Some("[user, user:*]"),
        "{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "grantees", "caller_grantees"),
        None,
        "{dsl}"
    );
    let outputs = translator(ConfidenceLevel::B, GRANTEE_HELPERS)
        .translate(&db_of(&schema))
        .expect("the schema should plan")
        .outputs()
        .expect("every clause should translate");
    let grants: Vec<&str> = outputs
        .tuple_queries()
        .iter()
        .map(|query| query.sql.as_str())
        .filter(|sql| sql.contains("FROM \"public\".\"project_grants\""))
        .collect();
    let joining = |subject: &str, kinds: &str| {
        grants
            .iter()
            .filter(|sql| sql.contains(subject) && sql.contains(kinds))
            .count()
    };
    assert_eq!(grants.len(), 3, "{grants:#?}");
    assert_eq!(
        joining(
            "'user:' ||",
            "\"kind\" IN ('user', 'team', 'organization', 'everyone', 'signed_in')"
        ),
        1,
        "{grants:#?}"
    );
    assert_eq!(
        joining("'user:*'", "\"kind\" IN ('everyone')"),
        1,
        "{grants:#?}"
    );
    assert_eq!(
        joining("'user:*'", "\"kind\" IN ('signed_in')"),
        1,
        "{grants:#?}"
    );
}

/// A gate on the arm naming the set keeps none of its rows for the constant it names,
/// so every grantee the set holds holds the grant but that caller.
#[test]
fn a_caller_gate_on_a_grant_naming_a_set_excludes_the_constant_from_every_grantee() {
    let dsl = model(
        &GRANTEES.replace(
            "IN (SELECT authz.caller_grantees())",
            "IN (SELECT authz.caller_grantees()) \
             AND current_setting('app.user_id', true) <> 'anonymous'",
        ),
        GRANTEE_HELPERS,
    );
    let definition = |relation: &str| {
        relation_definition(&dsl, "projects", relation).unwrap_or_else(|| panic!("{dsl}"))
    };
    assert_eq!(
        definition("projects_granted"),
        "project_grants_grantees but not project_grants_excluded"
    );
    assert_eq!(
        definition("project_grants_grantees"),
        "[grantees#caller_grantees]"
    );
    assert_eq!(definition("project_grants_excluded"), "[user]");
}

/// Each way a grant naming a set of grantees fails to name rows refuses the policy with
/// its own reason.
#[test]
fn a_grant_naming_a_set_that_names_no_rows_is_refused() {
    let cases = [
        (
            GRANTEES.to_owned(),
            &["authz.projects_granted"][..],
            "calls 'authz.caller_grantees', which is not declared",
        ),
        (
            GRANTEES.replace(
                "grantee_id TEXT NOT NULL REFERENCES grantees (id), PRIMARY",
                "grantee_id TEXT NOT NULL, PRIMARY",
            ),
            GRANTEE_HELPERS,
            "column 'grantee_id' of 'public.project_grants' names no row of one table",
        ),
        (
            GRANTEES.replace(
                "team_members (team_id TEXT NOT NULL REFERENCES teams (id)",
                "team_members (team_id TEXT NOT NULL",
            ),
            GRANTEE_HELPERS,
            "column 'team_id' of 'public.team_members' names no row of one table",
        ),
        (
            GRANTEES.replace(
                "organizations (id TEXT PRIMARY KEY REFERENCES grantees (id))",
                "organizations (id TEXT PRIMARY KEY)",
            ),
            GRANTEE_HELPERS,
            "column 'grantee_id' names rows of 'public.grantees', while declared helper \
             'authz.caller_grantees' returns keys of 'public.organizations'",
        ),
    ];
    for (schema, helpers, expected) in cases {
        let reason = refusal_of(&schema, helpers, "docs_read");
        assert!(reason.contains(expected), "{reason}");
    }
}

/// A walk down the teams holds the set on a team when it holds on the team's parent, and
/// the teams table loads each team's parent.
#[test]
fn a_walk_down_the_teams_holds_the_set_on_each_team_below() {
    let schema = GRANTEES.replace(
        "SELECT t.parent_id FROM public.teams t JOIN reached ON t.id = reached.id",
        "SELECT t.id FROM public.teams t JOIN reached ON t.parent_id = reached.id",
    );
    let dsl = model(&schema, GRANTEE_HELPERS);
    let caller_grantees =
        relation_definition(&dsl, "grantees", "caller_grantees").unwrap_or_else(|| panic!("{dsl}"));
    assert!(
        caller_grantees.ends_with(" or caller_grantees from grantees"),
        "{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "grantees", "grantees").as_deref(),
        Some("[grantees]"),
        "{dsl}"
    );
    let outputs = translator(ConfidenceLevel::B, GRANTEE_HELPERS)
        .translate(&db_of(&schema))
        .expect("the schema should plan")
        .outputs()
        .expect("every clause should translate");
    let parents: Vec<&str> = outputs
        .tuple_queries()
        .iter()
        .map(|query| query.sql.as_str())
        .filter(|sql| sql.contains("FROM \"public\".\"teams\"") && sql.contains("'grantees'"))
        .collect();
    assert_eq!(parents.len(), 1, "{:#?}", outputs.tuple_queries());
    assert!(parents[0].contains("\"parent_id\""), "{}", parents[0]);
}

/// Without a closed role column the caller's and the audiences' grant rows are kept by
/// their conditions alone, so the caller's arm grants every grantee row it names.
#[test]
fn a_set_of_the_caller_and_audiences_without_a_closed_kind_grants_users() {
    let schema =
        caller_and_audiences_only(GRANTEES).replace("kind TEXT NOT NULL CHECK", "kind TEXT CHECK");
    let outputs = translator(ConfidenceLevel::B, GRANTEE_HELPERS)
        .translate(&db_of(&schema))
        .expect("the schema should plan")
        .outputs()
        .expect("every clause should translate");
    let dsl = outputs.model();
    assert_eq!(
        relation_definition(&dsl, "projects", "project_grants").as_deref(),
        Some("[user, user:*]"),
        "{dsl}"
    );
    let grants: Vec<&str> = outputs
        .tuple_queries()
        .iter()
        .map(|query| query.sql.as_str())
        .filter(|sql| sql.contains("FROM \"public\".\"project_grants\""))
        .collect();
    assert_eq!(grants.len(), 3, "{grants:#?}");
    let callers: Vec<&str> = grants
        .iter()
        .copied()
        .filter(|sql| sql.contains("'user:' ||"))
        .collect();
    assert_eq!(callers.len(), 1, "{grants:#?}");
    assert!(!callers[0].contains("\"kind\""), "{}", callers[0]);
}

/// Grants kept from their start while their end is unset or ahead, as the request's
/// expiring grants are.
pub(crate) const EXPIRING: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE projects (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects (id),
  title TEXT);
CREATE TABLE project_grants (project_id TEXT NOT NULL REFERENCES projects (id),
  grantee_id TEXT NOT NULL, starts_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ,
  PRIMARY KEY (project_id, grantee_id));
GRANT SELECT ON project_grants TO authz_owner;
CREATE FUNCTION authz.projects_granted() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT pg.project_id FROM public.project_grants pg
  WHERE pg.grantee_id = current_setting('app.user_id', true)
    AND now() >= pg.starts_at
    AND (pg.expires_at IS NULL OR pg.expires_at > now())
$$;
ALTER FUNCTION authz.projects_granted() OWNER TO authz_owner;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_read ON docs FOR SELECT USING (
  project_id = ANY (ARRAY(SELECT authz.projects_granted())));
";

/// A row with no end meets the end at every instant, so its tuple compares the start
/// alone, and every other row's tuple compares both with the request clock.
#[test]
fn an_expiring_grant_is_a_tuple_conditioned_on_the_request_clock() {
    let dsl = model(EXPIRING, &["authz.projects_granted"]);
    let relation = |name: &str| relation_definition(&dsl, "projects", name);
    assert_eq!(
        relation("projects_granted").as_deref(),
        Some("member_1c2a7792 or member_1bf410e4"),
        "{dsl}"
    );
    let conditioned = |relation: Option<String>| {
        let condition = relation?
            .strip_prefix("[user with ")?
            .strip_suffix(']')?
            .to_string();
        let (_, body) = dsl.split_once(&format!("condition {condition}("))?;
        Some(
            body.split_once("{\n")?
                .1
                .split_once('\n')?
                .0
                .trim()
                .to_string(),
        )
    };
    assert_eq!(
        conditioned(relation("member_1c2a7792")).as_deref(),
        Some("starts_at <= request_time && expires_at > request_time"),
        "{dsl}"
    );
    assert_eq!(
        conditioned(relation("member_1bf410e4")).as_deref(),
        Some("starts_at <= request_time"),
        "{dsl}"
    );
}

/// Two rows of one caller on one project could each meet one bound, and no one tuple
/// says whether a single row meets both.
#[test]
fn several_bounds_over_rows_repeating_a_grant_are_refused() {
    let sql = EXPIRING.replace(",\n  PRIMARY KEY (project_id, grantee_id)", "");
    assert!(refusal_of(&sql, &["authz.projects_granted"], "docs_read")
        .contains("several clock bounds cannot be compressed into one fact"));
}

/// Four ends that may be unset take fifteen conditions, which a model admits, and five
/// take thirty-one, which none does.
#[test]
fn bounds_keeping_null_stop_at_the_conditions_a_model_admits() {
    let bounded = |ends: usize| {
        let mut columns = String::new();
        let mut conditions = String::new();
        for end in 1..=ends {
            let _ = write!(columns, ", ends_{end} TIMESTAMPTZ");
            let _ = write!(
                conditions,
                "\n    AND (pg.ends_{end} IS NULL OR pg.ends_{end} > now())"
            );
        }
        EXPIRING
            .replace(
                "expires_at TIMESTAMPTZ,",
                &format!("expires_at TIMESTAMPTZ{columns},"),
            )
            .replace(
                "    AND now() >= pg.starts_at\n    AND (pg.expires_at IS NULL OR pg.expires_at > now())",
                &format!("    AND (pg.expires_at IS NULL OR pg.expires_at > now()){conditions}"),
            )
    };
    let helpers = &["authz.projects_granted"];
    let four_ends = using_of(&bounded(3), helpers, "docs_read");
    assert_eq!(four_ends.confidence, ConfidenceLevel::A, "{four_ends:?}");
    assert_eq!(
        relation_definition(&model(&bounded(3), helpers), "projects", "projects_granted")
            .map(|union| union.split(" or ").count()),
        Some(16)
    );
    assert!(refusal_of(&bounded(4), helpers, "docs_read")
        .contains("keeps NULL in 5 clock bounds, which takes more than the 25 conditions"));
}

/// A bound written either way round compares the column with the request clock the way
/// the body compares it with `now()`.
#[test]
fn each_clock_comparison_keeps_its_direction() {
    for (bound, compared) in [
        ("now() < pg.starts_at", "starts_at > request_time"),
        ("pg.starts_at >= now()", "starts_at >= request_time"),
        ("pg.starts_at < now()", "starts_at < request_time"),
        ("now() >= pg.starts_at", "starts_at <= request_time"),
    ] {
        let sql = EXPIRING.replace(
            "    AND now() >= pg.starts_at\n    AND (pg.expires_at IS NULL OR pg.expires_at > now())",
            &format!("    AND {bound}"),
        );
        let dsl = model(&sql, &["authz.projects_granted"]);
        let condition = dsl
            .split_once("\ncondition ")
            .and_then(|(_, body)| body.split_once("{\n"))
            .and_then(|(_, body)| body.split_once('\n'))
            .map(|(line, _)| line.trim());
        assert_eq!(condition, Some(compared), "{bound}: {dsl}");
    }
}

/// The audience helper over a deployment sending its caller as `data_type`.
fn typed_audience_translator(data_type: DataType) -> Translator {
    TranslatorBuilder::new(deployment([typed_caller("app.user_id", data_type)]))
        .with_min_confidence(ConfidenceLevel::B)
        .with_declared_helpers(AUDIENCE_HELPERS)
        .build()
}

/// The tuple queries loading `relation`.
fn queries_loading(translator: &Translator, sql: &str, relation: &str) -> Vec<String> {
    let needle = format!("'{relation}' AS relation");
    translator
        .translate(&db_of(sql))
        .expect("the schema should plan")
        .outputs()
        .expect("every clause should translate")
        .tuple_queries()
        .iter()
        .filter(|query| query.sql.contains(&needle))
        .map(|query| query.sql.clone())
        .collect()
}

/// The reason `translator` refuses the `USING` clause of `docs_read`.
fn audience_refusal(translator: &Translator, sql: &str) -> String {
    let classified = translator
        .classify(&db_of(sql))
        .into_iter()
        .find(|classified| classified.name() == "docs_read")
        .expect("docs_read should classify")
        .using_classification()
        .expect("USING should classify")
        .clone();
    assert_eq!(classified.confidence, ConfidenceLevel::D, "{classified:?}");
    match classified.pattern {
        PatternClass::Unknown(UnclassifiedExpr { reason, .. }) => reason,
        other => panic!("docs_read should be refused, got {other:?}"),
    }
}

/// One caller excluded in two spellings is loaded once.
#[test]
fn a_caller_excluded_in_two_spellings_is_loaded_once() {
    let sql = AUDIENCES.replace(
        "<> 'anonymous'",
        "<> $q$anonymous$q$ AND current_setting('app.user_id', true) <> 'anonymous'",
    );
    let excluded = queries_loading(
        &translator(ConfidenceLevel::B, AUDIENCE_HELPERS),
        &sql,
        "signed_in_excluded",
    );
    assert_eq!(excluded.len(), 1, "{excluded:#?}");
    assert!(
        excluded[0].contains("'user:anonymous' AS subject"),
        "{excluded:#?}"
    );
}

/// A `uuid` caller is excluded as the lowercase text a check sends, and a constant
/// spelled any other way is refused, as is a constant excluded from a caller whose
/// type has no canonical text read here.
#[test]
fn a_typed_caller_is_excluded_only_in_its_canonical_spelling() {
    let lowercase = "00000000-0000-0000-0000-00000000000a";
    let excluded = queries_loading(
        &typed_audience_translator(DataType::Uuid),
        &AUDIENCES.replace("'anonymous'", &format!("'{lowercase}'")),
        "signed_in_excluded",
    );
    assert_eq!(excluded.len(), 1, "{excluded:#?}");
    assert!(
        excluded[0].contains(&format!("'user:{lowercase}' AS subject")),
        "{excluded:#?}"
    );
    for (data_type, spelled) in [
        (DataType::Uuid, "'00000000-0000-0000-0000-00000000000A'"),
        (DataType::Uuid, "'00000000_0000-0000-0000-00000000000a'"),
        (DataType::Uuid, "'0000'"),
        (DataType::Integer(None), "'7'"),
    ] {
        let reason = audience_refusal(
            &typed_audience_translator(data_type),
            &AUDIENCES.replace("'anonymous'", spelled),
        );
        assert!(
            reason.contains(&format!("excludes the caller {spelled}")),
            "{reason}"
        );
    }
}

/// An arm keeping every row of a table with no declared roles grants each to every
/// caller, with no condition on the rows it loads.
#[test]
fn an_unfiltered_audience_arm_loads_every_row() {
    let sql = AUDIENCES
        .replace(
            " CHECK (visibility IN ('public', 'signed_in', 'private'))",
            "",
        )
        .replace(" WHERE p.visibility = 'public'", "");
    let dsl = model(&sql, AUDIENCE_HELPERS);
    assert_eq!(
        relation_definition(&dsl, "projects", "projects").as_deref(),
        Some("[user:*]"),
        "{dsl}"
    );
    let loading = queries_loading(
        &translator(ConfidenceLevel::B, AUDIENCE_HELPERS),
        &sql,
        "projects",
    );
    let unfiltered: Vec<&str> = loading
        .iter()
        .map(String::as_str)
        .filter(|query| query.contains("'user:*' AS subject"))
        .collect();
    assert_eq!(unfiltered.len(), 1, "{loading:#?}");
    assert!(!unfiltered[0].contains("\nAND ("), "{}", unfiltered[0]);
}

/// A role spelled as a number names no relation, so its audiences are named after the
/// table they read.
#[test]
fn an_audience_role_spelled_as_a_number_is_named_after_its_table() {
    let sql = AUDIENCES
        .replace(
            "visibility TEXT NOT NULL CHECK (visibility IN ('public', 'signed_in', 'private'))",
            "visibility INT NOT NULL CHECK (visibility IN (1, 2, 3))",
        )
        .replace("p.visibility = 'public'", "p.visibility = 1")
        .replace("p.visibility = 'signed_in'", "p.visibility = 2");
    let dsl = model(&sql, AUDIENCE_HELPERS);
    let definition = |relation: &str| {
        relation_definition(&dsl, "projects", relation).unwrap_or_else(|| panic!("{dsl}"))
    };
    assert_eq!(definition("projects"), "[user:*]");
    assert_eq!(definition("projects_everyone"), "[user:*]");
    assert_eq!(definition("projects_excluded"), "[user]");
}

/// Resources capped to the organization and kind pairs a table approves, the cap read
/// through a helper returning `TABLE (organization_id, kind)`.
const CAPS: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE resources (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, kind TEXT NOT NULL, owner_id TEXT NOT NULL);
CREATE TABLE approved_kinds (
  organization_id TEXT NOT NULL, kind TEXT NOT NULL, PRIMARY KEY (organization_id, kind));
GRANT SELECT ON resources, approved_kinds TO authz_owner;
CREATE FUNCTION authz.capped_kinds() RETURNS TABLE (organization_id TEXT, kind TEXT)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT approved.organization_id, approved.kind FROM public.approved_kinds approved
$$;
CREATE FUNCTION authz.capped_resources() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT resource.id FROM public.resources resource
  WHERE (resource.organization_id, resource.kind) IN (SELECT * FROM authz.capped_kinds())
$$;
CREATE FUNCTION authz.owned_resources() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT resource.id FROM public.resources resource
  WHERE resource.owner_id = current_setting('app.user_id', true)
    AND (resource.organization_id, resource.kind) IN (SELECT * FROM authz.capped_kinds())
$$;
ALTER FUNCTION authz.capped_kinds() OWNER TO authz_owner;
ALTER FUNCTION authz.capped_resources() OWNER TO authz_owner;
ALTER FUNCTION authz.owned_resources() OWNER TO authz_owner;
ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
";

/// A grant arm keeping only the rows a cap pairs with another helper's rows is refused,
/// whether a column or a request value is compared with the helper, since a relation
/// loaded from the arm alone would grant the rows the cap leaves out. So is an arm
/// returning several columns, which no one relation names.
#[test]
fn a_grant_arm_kept_by_a_cap_or_returning_several_columns_is_refused() {
    let helpers = [
        "authz.capped_kinds",
        "authz.capped_resources",
        "authz.owned_resources",
    ];
    let translator = TranslatorBuilder::new(deployment([
        caller("app.user_id"),
        scalar("app.installation_id"),
    ]))
    .with_min_confidence(ConfidenceLevel::B)
    .with_declared_helpers(helpers)
    .build();
    let capped = |helper: &str| {
        format!(
            "declared helper '{helper}' keeps the rows of 'public.resources' only where they \
             pair with the rows 'authz.capped_kinds' returns"
        )
    };
    for (using, reason) in [
        (
            "id = ANY (ARRAY(SELECT authz.capped_resources()))",
            capped("authz.capped_resources"),
        ),
        (
            "id = ANY (ARRAY(SELECT authz.owned_resources()))",
            capped("authz.owned_resources"),
        ),
        (
            "current_setting('app.installation_id', true) IN (SELECT authz.capped_resources())",
            capped("authz.capped_resources"),
        ),
        (
            "id IN (SELECT authz.capped_kinds())",
            "declared helper 'authz.capped_kinds' returns 2 columns of 'public.approved_kinds' \
             from one arm"
                .to_string(),
        ),
    ] {
        let sql =
            format!("{CAPS}CREATE POLICY resources_read ON resources FOR SELECT USING ({using});");
        let classified = translator
            .classify(&db_of(&sql))
            .into_iter()
            .find(|classified| classified.name() == "resources_read")
            .expect("resources_read should classify")
            .using_classification()
            .expect("USING should classify")
            .clone();
        assert_eq!(classified.confidence, ConfidenceLevel::D, "`{using}`");
        match classified.pattern {
            PatternClass::Unknown(UnclassifiedExpr {
                reason: refused, ..
            }) => {
                assert!(refused.contains(&reason), "`{using}`: {refused}");
            }
            other => panic!("`{using}` should be refused, got {other:?}"),
        }
    }
}
