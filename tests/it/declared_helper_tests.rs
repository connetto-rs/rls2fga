//! A column compared with the set a declared `SECURITY DEFINER` helper returns becomes
//! the grants the helper's body reads, `role from parent` through each parent arm.

use core::fmt::Write as _;

use rls2fga::classifier::patterns::{
    ClassifiedExpr, GrantRows, HelperSetArm, PatternClass, UnclassifiedExpr,
};
use rls2fga::generator::tuple_generator::SkippedTuples;
use rls2fga::parser::sql_parser::{SessionSetting, SettingValue};
use rls2fga::translator::{Translator, TranslatorBuilder};
use rls2fga::types::{AttributeLiteral, AttributePredicate, AttributeTest, ConfidenceLevel};
use rls2fga::types::{ColumnName, TranslationNote};
use sqlparser::ast::DataType;

use crate::support::deployment::{caller, delimited_set, deployment, scalar};
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
            "compares a column with setting `app.tenant` as the identity of a principal, \
             which it is not",
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

/// A request value behind a helper falls closed where the rows it reads depend on the
/// request or on the statement time, and a column compared with rows every request
/// gets alike names no grantee.
#[test]
fn request_values_the_gates_cannot_carry_are_refused() {
    let policy = |using: &str| {
        format!(
            "{LEVELS}{OWNER_READS}{REQUEST_VALUES}
             CREATE TABLE expiring_links (id TEXT PRIMARY KEY, expires_at TIMESTAMPTZ NOT NULL);
             GRANT SELECT ON expiring_links TO authz_owner;
             CREATE FUNCTION authz.every_link() RETURNS SETOF TEXT
             LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
               SELECT l.id FROM public.share_links l WHERE l.revoked = FALSE
             $$;
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
             CREATE FUNCTION authz.signed_in_links() RETURNS SETOF TEXT
             LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
               SELECT l.id FROM public.share_links l
               WHERE l.id = ANY (string_to_array(current_setting('app.link_ids', true), ','))
                 AND current_setting('app.user_id', true) <> ''
             $$;
             ALTER FUNCTION authz.every_link() OWNER TO authz_owner;
             ALTER FUNCTION authz.live_links() OWNER TO authz_owner;
             ALTER FUNCTION authz.live_ids() OWNER TO authz_owner;
             ALTER FUNCTION authz.signed_in_links() OWNER TO authz_owner;
             CREATE FUNCTION authz.allowing_twice(target TEXT) RETURNS SETOF TEXT
             LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
               SELECT ip.installation_id FROM public.installation_permissions ip
               WHERE ip.table_name = target
             $$;
             CREATE FUNCTION authz.allowing_twice(target INT) RETURNS SETOF TEXT
             LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
               SELECT ip.installation_id FROM public.installation_permissions ip
             $$;
             CREATE FUNCTION authz.caller_teams() RETURNS SETOF TEXT
             LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
               SELECT g.team_id FROM public.team_grants g
               WHERE g.principal_id = current_setting('app.user_id', true)
             $$;
             CREATE FUNCTION authz.team_projects() RETURNS SETOF TEXT
             LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
               SELECT pg.project_id FROM public.project_grants pg
               WHERE pg.principal_id IN (SELECT authz.caller_teams())
             $$;
             ALTER FUNCTION authz.allowing_twice(TEXT) OWNER TO authz_owner;
             ALTER FUNCTION authz.allowing_twice(INT) OWNER TO authz_owner;
             ALTER FUNCTION authz.caller_teams() OWNER TO authz_owner;
             ALTER FUNCTION authz.team_projects() OWNER TO authz_owner;
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
        "authz.every_link",
        "authz.live_links",
        "authz.live_ids",
        "authz.signed_in_links",
        "authz.allowing_twice",
        "authz.caller_teams",
        "authz.team_projects",
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
            "link_id = ANY (ARRAY(SELECT authz.every_link()))",
            "to every request alike, and no grantee stands for every caller",
        ),
        (
            "link_id = ANY (ARRAY(SELECT authz.signed_in_links()))",
            "keeps the rows of 'public.share_links' only while a caller setting is set",
        ),
        (
            "current_setting('app.installation_id', true) IN (SELECT authz.signed_in_links())",
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
        (
            "project_id = ANY (ARRAY(SELECT authz.team_projects()))",
            "naming a grantee 'authz.caller_teams' returns",
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

/// An arm comparing a column with another principal than the caller, and an arm capped
/// by another helper's rows, each keep other rows than a grant to the caller, so each is
/// refused.
#[test]
fn principal_and_capped_arms_are_refused() {
    let sql = "
        CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
        CREATE SCHEMA authz;
        GRANT USAGE ON SCHEMA authz TO authz_owner;
        CREATE TABLE resources (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL,
          kind TEXT NOT NULL, owner_id TEXT NOT NULL);
        CREATE TABLE resource_grants (resource_id TEXT NOT NULL REFERENCES resources (id),
          principal_id TEXT NOT NULL, role TEXT NOT NULL,
          PRIMARY KEY (resource_id, principal_id));
        CREATE TABLE installation_permissions (installation_id TEXT NOT NULL,
          organization_id TEXT NOT NULL, kind TEXT NOT NULL,
          PRIMARY KEY (installation_id, organization_id, kind));
        GRANT SELECT ON resources, resource_grants, installation_permissions TO authz_owner;
        CREATE FUNCTION authz.installation_resources() RETURNS SETOF TEXT
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
          SELECT g.resource_id FROM public.resource_grants g
          WHERE g.principal_id = current_setting('app.installation_id', true)
        $$;
        CREATE FUNCTION authz.capped_kinds() RETURNS TABLE (organization_id TEXT, kind TEXT)
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
          SELECT p.organization_id, p.kind FROM public.installation_permissions p
          WHERE p.installation_id = current_setting('app.installation_id', true)
        $$;
        CREATE FUNCTION authz.owned_resources() RETURNS SETOF TEXT
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
          SELECT r.id FROM public.resources r
          WHERE r.owner_id = current_setting('app.user_id', true)
            AND (current_setting('app.installation_id', true) IS NULL
              OR (r.organization_id, r.kind) IN (SELECT * FROM authz.capped_kinds()))
        $$;
        ALTER FUNCTION authz.installation_resources() OWNER TO authz_owner;
        ALTER FUNCTION authz.capped_kinds() OWNER TO authz_owner;
        ALTER FUNCTION authz.owned_resources() OWNER TO authz_owner;
        CREATE TABLE notes (id TEXT PRIMARY KEY, resource_id TEXT NOT NULL REFERENCES resources (id));
        ALTER TABLE notes ENABLE ROW LEVEL SECURITY;";
    let installation = SessionSetting::value(
        "app.installation_id",
        SettingValue::Principal {
            kind: "installation".to_string(),
            identity: DataType::Text,
        },
    )
    .expect("a custom setting name");
    let translator = TranslatorBuilder::new(deployment([caller("app.user_id"), installation]))
        .with_min_confidence(ConfidenceLevel::B)
        .with_declared_helpers([
            "authz.installation_resources",
            "authz.capped_kinds",
            "authz.owned_resources",
        ])
        .build();
    let cases = [
        (
            "resource_id = ANY (ARRAY(SELECT authz.installation_resources()))",
            "keeps the rows of 'public.resource_grants' whose 'principal_id' holds the \
             request's installation",
        ),
        (
            "resource_id = ANY (ARRAY(SELECT authz.owned_resources()))",
            "caps the rows of 'public.resources' by the rows another helper returns",
        ),
    ];
    let mut mismatches = String::new();
    for (using, reason) in cases {
        let schema =
            format!("{sql}\nCREATE POLICY notes_read ON notes FOR SELECT USING ({using});");
        let classified = translator
            .classify(&db_of(&schema))
            .into_iter()
            .find(|classified| classified.name() == "notes_read")
            .expect("notes_read should classify")
            .using_classification()
            .expect("USING should classify")
            .clone();
        match classified.pattern {
            PatternClass::Unknown(UnclassifiedExpr {
                reason: refused, ..
            }) if refused.contains(reason) => {}
            other => writeln!(mismatches, "`{using}` should be refused, got {other:?}")
                .expect("writing to a String"),
        }
    }
    assert!(mismatches.is_empty(), "{mismatches}");
}
