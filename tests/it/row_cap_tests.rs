//! Grant arms of a declared helper capped by the pairs another helper returns.

use rls2fga::classifier::patterns::{PatternClass, UnclassifiedExpr};
use rls2fga::translator::{Translator, TranslatorBuilder};
use rls2fga::types::ConfidenceLevel;
use sqlparser::ast::DataType;

use crate::support::deployment::{deployment, principal, typed_caller};
use crate::support::footgun::{db_of, relation_definition, type_names};

/// Organizations a member reads, and the notes of those organizations, capped by the literal
/// kind `organization` while an app installation acts for the member, and the resources a
/// caller owns, capped by the organization and kind each resource carries. An installation
/// holds one role per kind in its organization.
pub(crate) const INSTALLATION_CAPS: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TYPE authz.role AS ENUM ('reader', 'writer', 'admin');
CREATE TYPE authz.resource_kind AS ENUM ('organization', 'project');
CREATE TABLE organizations (id UUID PRIMARY KEY);
CREATE TABLE memberships (
  organization_id UUID NOT NULL REFERENCES organizations (id),
  user_id UUID NOT NULL,
  PRIMARY KEY (organization_id, user_id)
);
CREATE TABLE app_installations (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES organizations (id),
  UNIQUE (organization_id, id)
);
CREATE TABLE installation_permissions (
  installation_id UUID NOT NULL,
  organization_id UUID NOT NULL,
  kind authz.resource_kind NOT NULL,
  max_role authz.role NOT NULL,
  PRIMARY KEY (installation_id, kind),
  FOREIGN KEY (organization_id, installation_id) REFERENCES app_installations (organization_id, id)
);
CREATE TABLE organization_notes (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES organizations (id)
);
CREATE TABLE resources (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES organizations (id),
  kind authz.resource_kind NOT NULL,
  owner_id UUID NOT NULL
);
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON memberships, installation_permissions, resources TO authz_owner;
CREATE FUNCTION authz.caller_id() RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT NULLIF(current_setting('app.user_id', true), '')::uuid
$$;
CREATE FUNCTION authz.acting_installation_id() RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT NULLIF(current_setting('app.installation_id', true), '')::uuid
$$;
CREATE FUNCTION authz.capped_kinds(min_role authz.role)
RETURNS TABLE (organization_id UUID, kind authz.resource_kind)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT permission.organization_id, permission.kind FROM public.installation_permissions permission
  WHERE permission.installation_id = authz.acting_installation_id()
    AND permission.max_role >= min_role
$$;
CREATE FUNCTION authz.member_organizations() RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT membership.organization_id FROM public.memberships membership
  WHERE membership.user_id = authz.caller_id()
    AND (authz.acting_installation_id() IS NULL
      OR (membership.organization_id, 'organization'::authz.resource_kind)
        IN (SELECT * FROM authz.capped_kinds('reader')))
$$;
CREATE FUNCTION authz.owned_resources() RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT resource.id FROM public.resources resource
  WHERE resource.owner_id = authz.caller_id()
    AND (authz.acting_installation_id() IS NULL
      OR (resource.organization_id, resource.kind) IN (SELECT * FROM authz.capped_kinds('writer')))
$$;
ALTER FUNCTION authz.caller_id() OWNER TO authz_owner;
ALTER FUNCTION authz.acting_installation_id() OWNER TO authz_owner;
ALTER FUNCTION authz.capped_kinds(authz.role) OWNER TO authz_owner;
ALTER FUNCTION authz.member_organizations() OWNER TO authz_owner;
ALTER FUNCTION authz.owned_resources() OWNER TO authz_owner;
CREATE POLICY organizations_select ON organizations FOR SELECT
  USING (id = ANY (ARRAY(SELECT authz.member_organizations())));
CREATE POLICY organization_notes_select ON organization_notes FOR SELECT
  USING (organization_id IN (SELECT authz.member_organizations()));
CREATE POLICY resources_select ON resources FOR SELECT
  USING (id = ANY (ARRAY(SELECT authz.owned_resources())));
";

/// The helpers [`INSTALLATION_CAPS`] declares.
pub(crate) const CAP_HELPERS: &[&str] = &[
    "authz.capped_kinds",
    "authz.member_organizations",
    "authz.owned_resources",
];

/// The caller and the installation acting for it, either of which a request may leave
/// unset, with `helpers` declared.
pub(crate) fn installation_translator(helpers: &[&str]) -> Translator {
    TranslatorBuilder::new(deployment([
        typed_caller("app.user_id", DataType::Uuid).may_be_unset(),
        principal("app.installation_id", "installation", DataType::Uuid).may_be_unset(),
    ]))
    .with_min_confidence(ConfidenceLevel::B)
    .with_declared_helpers(helpers.iter().copied())
    .build()
}

/// The `USING` classification of `policy` in `schema`, with `helpers` declared.
fn using_of(
    schema: &str,
    helpers: &[&str],
    policy: &str,
) -> rls2fga::classifier::patterns::ClassifiedExpr {
    installation_translator(helpers)
        .classify(&db_of(schema))
        .into_iter()
        .find(|classified| classified.name() == policy)
        .unwrap_or_else(|| panic!("{policy} should classify"))
        .using_classification()
        .unwrap_or_else(|| panic!("{policy} USING should classify"))
        .clone()
}

/// A cap by a literal beside the level's row, on the level's own table and on a table
/// referencing it, and a cap by the columns of the row it keeps, translate.
#[test]
fn caps_by_a_literal_kind_or_by_the_row_kind_translate() {
    for policy in [
        "organizations_select",
        "organization_notes_select",
        "resources_select",
    ] {
        let using = using_of(INSTALLATION_CAPS, CAP_HELPERS, policy);
        assert!(
            !matches!(using.pattern, PatternClass::Unknown(_)),
            "{policy}: {:?}",
            using.pattern
        );
    }
    installation_translator(CAP_HELPERS)
        .translate(&db_of(INSTALLATION_CAPS))
        .expect("the schema plans")
        .outputs()
        .expect("the schema translates");
}

/// Team members an installation acting for their user may administer, through the
/// membership each member row joins. `administered_teams` caps a member row by its
/// membership's organization beside the literal kind `organization`, `capped_teams` by the
/// member row's own organization beside that literal, and `scoped_teams` by the
/// membership's organization and the kind its scope names.
pub(crate) const JOINED_CAPS: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TYPE authz.role AS ENUM ('reader', 'writer', 'admin');
CREATE TYPE authz.resource_kind AS ENUM ('organization', 'project');
CREATE TABLE organizations (id UUID PRIMARY KEY);
CREATE TABLE memberships (
  organization_id UUID NOT NULL REFERENCES organizations (id),
  user_id UUID NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('active', 'deactivated')),
  scope authz.resource_kind NOT NULL,
  PRIMARY KEY (organization_id, user_id)
);
CREATE TABLE app_installations (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES organizations (id),
  UNIQUE (organization_id, id)
);
CREATE TABLE installation_permissions (
  installation_id UUID NOT NULL,
  organization_id UUID NOT NULL,
  kind authz.resource_kind NOT NULL,
  max_role authz.role NOT NULL,
  PRIMARY KEY (installation_id, kind),
  FOREIGN KEY (organization_id, installation_id) REFERENCES app_installations (organization_id, id)
);
CREATE TABLE teams (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES organizations (id)
);
CREATE TABLE team_members (
  team_id UUID NOT NULL REFERENCES teams (id),
  organization_id UUID NOT NULL,
  user_id UUID NOT NULL,
  team_role TEXT NOT NULL CHECK (team_role IN ('member', 'admin')),
  PRIMARY KEY (team_id, user_id),
  FOREIGN KEY (organization_id, user_id) REFERENCES memberships (organization_id, user_id)
);
ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_members ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON memberships, installation_permissions, team_members TO authz_owner;
CREATE FUNCTION authz.caller_id() RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT NULLIF(current_setting('app.user_id', true), '')::uuid
$$;
CREATE FUNCTION authz.acting_installation_id() RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT NULLIF(current_setting('app.installation_id', true), '')::uuid
$$;
CREATE FUNCTION authz.capped_kinds(min_role authz.role)
RETURNS TABLE (organization_id UUID, kind authz.resource_kind)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT permission.organization_id, permission.kind FROM public.installation_permissions permission
  WHERE permission.installation_id = authz.acting_installation_id()
    AND permission.max_role >= min_role
$$;
CREATE FUNCTION authz.administered_teams() RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT member.team_id FROM public.team_members member
  JOIN public.memberships membership ON membership.organization_id = member.organization_id AND membership.user_id = member.user_id
  WHERE member.user_id = authz.caller_id()
    AND member.team_role = 'admin' AND membership.state = 'active'
    AND (authz.acting_installation_id() IS NULL
      OR (membership.organization_id, 'organization'::authz.resource_kind)
        IN (SELECT * FROM authz.capped_kinds('admin')))
$$;
CREATE FUNCTION authz.capped_teams() RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT member.team_id FROM public.team_members member
  WHERE member.user_id = authz.caller_id()
    AND (authz.acting_installation_id() IS NULL
      OR (member.organization_id, 'organization'::authz.resource_kind)
        IN (SELECT * FROM authz.capped_kinds('writer')))
$$;
CREATE FUNCTION authz.scoped_teams() RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT member.team_id FROM public.team_members member
  JOIN public.memberships membership ON membership.organization_id = member.organization_id AND membership.user_id = member.user_id
  WHERE member.user_id = authz.caller_id()
    AND (authz.acting_installation_id() IS NULL
      OR (membership.organization_id, membership.scope) IN (SELECT * FROM authz.capped_kinds('reader')))
$$;
ALTER FUNCTION authz.caller_id() OWNER TO authz_owner;
ALTER FUNCTION authz.acting_installation_id() OWNER TO authz_owner;
ALTER FUNCTION authz.capped_kinds(authz.role) OWNER TO authz_owner;
ALTER FUNCTION authz.administered_teams() OWNER TO authz_owner;
ALTER FUNCTION authz.capped_teams() OWNER TO authz_owner;
ALTER FUNCTION authz.scoped_teams() OWNER TO authz_owner;
CREATE POLICY team_members_select ON team_members FOR SELECT
  USING (team_id = ANY (ARRAY(SELECT authz.administered_teams())));
";

/// The helpers [`JOINED_CAPS`] declares.
pub(crate) const JOINED_CAP_HELPERS: &[&str] = &[
    "authz.capped_kinds",
    "authz.administered_teams",
    "authz.capped_teams",
    "authz.scoped_teams",
];

/// [`JOINED_CAPS`] with the teams read through `helper`.
pub(crate) fn joined_caps_reading(helper: &str) -> String {
    format!(
        "{JOINED_CAPS}CREATE POLICY teams_read ON teams FOR SELECT \
         USING (id IN (SELECT authz.{helper}()));"
    )
}

/// A cap by a joined row's columns, by a column other than the returned one beside a
/// literal, and by the joined row's own columns grades A, each member row its own object.
#[test]
fn caps_by_joined_rows_and_by_columns_beside_literals_translate() {
    for helper in ["administered_teams", "capped_teams", "scoped_teams"] {
        let schema = joined_caps_reading(helper);
        for policy in ["teams_read", "team_members_select"] {
            let using = using_of(&schema, JOINED_CAP_HELPERS, policy);
            assert_eq!(
                using.confidence,
                ConfidenceLevel::A,
                "{helper} {policy}: {:?}",
                using.pattern
            );
        }
        installation_translator(JOINED_CAP_HELPERS)
            .translate(&db_of(&schema))
            .expect("the schema plans")
            .outputs()
            .expect("the schema translates");
    }
}

/// A table already named like a cap's pair type keeps its type, and the pairs move to a
/// type of their own, holding whoever the cap returns them to.
#[test]
fn a_pair_type_named_like_a_table_takes_a_name_of_its_own() {
    let schema =
        format!("{INSTALLATION_CAPS}CREATE TABLE capped_kinds_reader_pair (id UUID PRIMARY KEY);");
    let dsl = installation_translator(CAP_HELPERS)
        .translate(&db_of(&schema))
        .expect("the schema plans")
        .outputs()
        .expect("the schema translates")
        .model()
        .clone();
    assert_eq!(
        relation_definition(&dsl, "capped_kinds_reader_pair", "capped_kinds_reader"),
        None,
        "{dsl}"
    );
    let pairs: Vec<String> = type_names(&dsl)
        .into_iter()
        .filter(|name| name.starts_with("capped_kinds_reader_pair_"))
        .collect();
    let [pairs] = pairs.as_slice() else {
        panic!("one renamed pair type expected, got {pairs:?}\n{dsl}");
    };
    assert_eq!(
        relation_definition(&dsl, pairs, "capped_kinds_reader").as_deref(),
        Some("actor from member_installation"),
        "{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "organizations", pairs).as_deref(),
        Some(format!("[{pairs}]").as_str()),
        "{dsl}"
    );
}

/// A cap the model cannot keep is refused naming why, never dropped.
#[test]
fn caps_with_no_pair_relation_are_refused() {
    let lifted = "authz.acting_installation_id() IS NULL";
    let capped = "(SELECT * FROM authz.capped_kinds('reader'))";
    let reader_kinds = |condition: &str| {
        format!(
            "{INSTALLATION_CAPS}CREATE FUNCTION authz.reader_kinds()
RETURNS TABLE (organization_id UUID, kind authz.resource_kind)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT permission.organization_id, permission.kind FROM public.installation_permissions permission
  WHERE {condition}
$$;
ALTER FUNCTION authz.reader_kinds() OWNER TO authz_owner;
"
        )
        .replace(capped, "(SELECT * FROM authz.reader_kinds())")
    };
    let notes = "CREATE TABLE kind_notes (
  organization_id UUID NOT NULL REFERENCES organizations (id),
  kind authz.resource_kind NOT NULL,
  author_id UUID NOT NULL
);
GRANT SELECT ON kind_notes TO authz_owner;
CREATE FUNCTION authz.noted_organizations() RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT note.organization_id FROM public.kind_notes note
  WHERE note.author_id = authz.caller_id()
    AND (note.organization_id, note.kind) IN (SELECT * FROM authz.capped_kinds('reader'))
$$;
ALTER FUNCTION authz.noted_organizations() OWNER TO authz_owner;
CREATE POLICY organizations_noted ON organizations FOR SELECT
  USING (id IN (SELECT authz.noted_organizations()));
";
    for (rewritten, policy, reason) in [
        (
            INSTALLATION_CAPS.replace(
                lifted,
                "current_setting('app.installation_id', true)::uuid IS NULL",
            ),
            "organizations_select",
            "declared helper 'authz.member_organizations' lifts its cap where setting \
             'app.installation_id' reads NULL, but reads it without NULLIF(..., '')",
        ),
        (
            INSTALLATION_CAPS.replace(
                lifted,
                "NULLIF(current_setting('app.installation_id'), '')::uuid IS NULL",
            ),
            "organizations_select",
            "declared helper 'authz.member_organizations' lifts its cap where setting \
             'app.installation_id' reads NULL, but reads it through current_setting without \
             missing_ok, which raises 42704",
        ),
        (
            INSTALLATION_CAPS.replace(
                "(membership.organization_id, 'organization'::authz.resource_kind)",
                "('00000000-0000-0000-0000-000000000000'::uuid, 'organization'::authz.resource_kind)",
            ),
            "organizations_select",
            "declared helper 'authz.member_organizations' pairs literals with the rows \
             'authz.capped_kinds' returns beside no column of 'public.memberships'",
        ),
        (
            format!("{INSTALLATION_CAPS}{notes}"),
            "organizations_noted",
            "declared helper 'authz.noted_organizations' pairs column 'kind' of \
             'public.kind_notes' with the rows 'authz.capped_kinds' returns, while several rows \
             of 'public.kind_notes' can return one row and no key names each of its rows",
        ),
        (
            joined_caps_reading("scoped_teams").replace(
                "(membership.organization_id, membership.scope)",
                "(member.team_id, membership.scope)",
            ),
            "teams_read",
            "declared helper 'authz.scoped_teams' pairs columns of 'public.team_members' and of \
             'public.memberships' with the rows 'authz.capped_kinds' returns, which no one row \
             holds",
        ),
        (
            joined_caps_reading("scoped_teams").replace(
                "scope authz.resource_kind NOT NULL",
                "scope TEXT NOT NULL",
            ),
            "teams_read",
            "declared helper 'authz.scoped_teams' pairs column 'scope' of 'public.memberships' \
             with column 'kind' of the rows 'authz.capped_kinds' returns, and the two are not \
             of one type",
        ),
        (
            reader_kinds("permission.installation_id = authz.acting_installation_id()")
                .replace("authz.reader_kinds", "authz.undeclared_kinds"),
            "organizations_select",
            "declared helper 'authz.member_organizations' calls 'authz.undeclared_kinds', \
             which is not declared",
        ),
        (
            reader_kinds(
                "(permission.organization_id, permission.kind) \
                 IN (SELECT * FROM authz.capped_kinds('admin'))",
            ),
            "organizations_select",
            "declared helper 'authz.member_organizations' is capped by 'authz.reader_kinds', \
             whose own rows 'authz.capped_kinds' caps",
        ),
        (
            INSTALLATION_CAPS.replace(
                lifted,
                "NULLIF(current_setting('app.user_id', true), '')::uuid IS NULL",
            ),
            "organizations_select",
            "declared helper 'authz.member_organizations' lifts its cap where setting \
             'app.user_id' reads NULL, which the deployment does not declare as one value a \
             request may leave unset",
        ),
        (
            INSTALLATION_CAPS.replace(
                "'organization'::authz.resource_kind)",
                "NULL::authz.resource_kind)",
            ),
            "organizations_select",
            "declared helper 'authz.member_organizations' pairs 'NULL' with the rows \
             'authz.capped_kinds' returns, which is no literal a pair is named by",
        ),
        (
            format!(
                "{INSTALLATION_CAPS}CREATE FUNCTION authz.installation_organizations()
RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT installation.organization_id FROM public.app_installations installation
  WHERE installation.id = authz.acting_installation_id()
$$;
CREATE FUNCTION authz.installation_resources() RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT resource.id FROM public.resources resource
  WHERE resource.organization_id IN (SELECT authz.installation_organizations())
$$;
GRANT SELECT ON app_installations TO authz_owner;
ALTER FUNCTION authz.installation_organizations() OWNER TO authz_owner;
ALTER FUNCTION authz.installation_resources() OWNER TO authz_owner;
"
            )
            .replace(
                "(resource.organization_id, resource.kind) \
                 IN (SELECT * FROM authz.capped_kinds('writer'))",
                "resource.id IN (SELECT authz.installation_resources())",
            ),
            "resources_select",
            "declared helper 'authz.owned_resources' is capped by \
             'authz.installation_resources', which returns pairs through a parent or a walk",
        ),
        (
            INSTALLATION_CAPS.replace(
                "kind authz.resource_kind NOT NULL,\n  owner_id",
                "kind TEXT NOT NULL,\n  owner_id",
            ),
            "resources_select",
            "declared helper 'authz.owned_resources' pairs column 'kind' of 'public.resources' \
             with column 'kind' of the rows 'authz.capped_kinds' returns, and the two are not \
             of one type",
        ),
    ] {
        let helpers = [
            CAP_HELPERS,
            JOINED_CAP_HELPERS,
            &[
                "authz.noted_organizations",
                "authz.reader_kinds",
                "authz.installation_organizations",
                "authz.installation_resources",
            ],
        ]
        .concat();
        let using = using_of(&rewritten, &helpers, policy);
        assert_eq!(using.confidence, ConfidenceLevel::D, "{reason}");
        match using.pattern {
            PatternClass::Unknown(UnclassifiedExpr {
                reason: refused, ..
            }) => assert!(refused.contains(reason), "expected {reason}, got {refused}"),
            other => panic!("{policy} should be refused with {reason}, got {other:?}"),
        }
    }
}

/// Projects, invitations and reports whose policies cap an installation acting for the
/// caller by the pairs `authz.capped_kinds` returns, lifted where no installation acts.
/// `projects` reads the pairs through `*`, `reports` through the returned columns, and
/// `invitations` pairs its organization with the literal kind `organization`, beside the
/// invitee or a member of the invitation's organization.
pub(crate) const POLICY_CAPS: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TYPE authz.role AS ENUM ('reader', 'writer', 'admin');
CREATE TYPE authz.resource_kind AS ENUM ('organization', 'project');
CREATE TABLE organizations (id UUID PRIMARY KEY);
CREATE TABLE memberships (
  organization_id UUID NOT NULL REFERENCES organizations (id),
  user_id UUID NOT NULL,
  PRIMARY KEY (organization_id, user_id)
);
CREATE TABLE installation_permissions (
  installation_id UUID NOT NULL,
  organization_id UUID NOT NULL REFERENCES organizations (id),
  kind authz.resource_kind NOT NULL,
  max_role authz.role NOT NULL,
  PRIMARY KEY (installation_id, organization_id, kind)
);
CREATE TABLE projects (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES organizations (id),
  kind authz.resource_kind NOT NULL
);
CREATE TABLE reports (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES organizations (id),
  kind authz.resource_kind NOT NULL
);
CREATE TABLE invitations (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES organizations (id),
  invitee_id UUID NOT NULL
);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON memberships, installation_permissions TO authz_owner;
CREATE FUNCTION authz.caller_id() RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT NULLIF(current_setting('app.user_id', true), '')::uuid
$$;
CREATE FUNCTION authz.acting_installation_id() RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT NULLIF(current_setting('app.installation_id', true), '')::uuid
$$;
CREATE FUNCTION authz.capped_kinds(min_role authz.role)
RETURNS TABLE (organization_id UUID, kind authz.resource_kind)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT permission.organization_id, permission.kind FROM public.installation_permissions permission
  WHERE permission.installation_id = authz.acting_installation_id()
    AND permission.max_role >= min_role
$$;
CREATE FUNCTION authz.member_organizations() RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT membership.organization_id FROM public.memberships membership
  WHERE membership.user_id = authz.caller_id()
$$;
ALTER FUNCTION authz.caller_id() OWNER TO authz_owner;
ALTER FUNCTION authz.acting_installation_id() OWNER TO authz_owner;
ALTER FUNCTION authz.capped_kinds(authz.role) OWNER TO authz_owner;
ALTER FUNCTION authz.member_organizations() OWNER TO authz_owner;
CREATE POLICY projects_capped ON projects FOR SELECT
  USING ((SELECT authz.acting_installation_id()) IS NULL
    OR (organization_id, kind) IN (SELECT * FROM authz.capped_kinds('writer')));
CREATE POLICY reports_capped ON reports FOR SELECT
  USING ((SELECT authz.acting_installation_id()) IS NULL
    OR (organization_id, kind) IN (SELECT capped.organization_id, capped.kind
      FROM authz.capped_kinds('reader') capped));
CREATE POLICY invitations_capped ON invitations FOR SELECT
  USING ((invitee_id = (SELECT authz.caller_id())
      OR organization_id IN (SELECT authz.member_organizations()))
    AND ((SELECT authz.acting_installation_id()) IS NULL
      OR (organization_id, 'organization'::authz.resource_kind)
        IN (SELECT * FROM authz.capped_kinds('reader'))));
";

/// The helpers [`POLICY_CAPS`] declares.
pub(crate) const POLICY_CAP_HELPERS: &[&str] =
    &["authz.capped_kinds", "authz.member_organizations"];

/// A policy clause capped by a declared helper's pairs grades A, translates and is reported
/// by its README row.
#[test]
fn policy_clauses_capped_by_helper_pairs_translate() {
    let listed = "SELECT capped.organization_id, capped.kind\n      FROM authz.capped_kinds('reader') capped";
    for schema in [
        POLICY_CAPS.to_string(),
        POLICY_CAPS.replace(
            listed,
            "SELECT capped.* FROM authz.capped_kinds('reader') capped",
        ),
        POLICY_CAPS.replace(
            listed,
            "SELECT capped.org, capped.k FROM authz.capped_kinds('reader') AS capped(org, k)",
        ),
    ] {
        for policy in ["projects_capped", "reports_capped", "invitations_capped"] {
            let using = using_of(&schema, POLICY_CAP_HELPERS, policy);
            assert_eq!(
                using.confidence,
                ConfidenceLevel::A,
                "{policy}: {:?}",
                using.pattern
            );
        }
    }
    let capped = "USING ((SELECT authz.acting_installation_id()) IS NULL\n    \
                  OR (organization_id, kind) IN (SELECT * FROM authz.capped_kinds('writer')));";
    for (operands, row) in [
        (
            "organization_id, kind",
            "P30 ((organization_id, kind) in authz.capped_kinds('writer'))",
        ),
        (
            "organization_id, 'organization'::authz.resource_kind",
            "P30 ((organization_id, 'organization') in authz.capped_kinds('writer'))",
        ),
    ] {
        let schema = POLICY_CAPS.replace(
            capped,
            &format!("USING (({operands}) IN (SELECT * FROM authz.capped_kinds('writer')));"),
        );
        let report = installation_translator(POLICY_CAP_HELPERS)
            .translate(&db_of(&schema))
            .expect("the schema plans")
            .outputs()
            .expect("the schema translates")
            .report();
        assert!(report.contains(row), "{row} in {report}");
    }
}

/// A policy cap on a table no key names a row of is refused naming the pair links it drops.
#[test]
fn a_policy_cap_on_a_table_without_a_key_names_the_dropped_pair_links() {
    let schema = POLICY_CAPS.replacen(
        "id UUID PRIMARY KEY,\n  organization_id",
        "id UUID,\n  organization_id",
        1,
    );
    let refused = installation_translator(POLICY_CAP_HELPERS)
        .translate(&db_of(&schema))
        .expect("the schema plans")
        .outputs()
        .expect_err("no row of 'projects' can be named");
    assert!(
        format!("{refused:?}").contains("helper pair links"),
        "{refused:?}"
    );
}

/// A policy cap no pair object can keep is refused naming why.
#[test]
fn policy_caps_with_no_pair_relation_are_refused() {
    let star = "(organization_id, kind) IN (SELECT * FROM authz.capped_kinds('writer'))";
    for (schema, helpers, policy, reason) in [
        (
            POLICY_CAPS.to_string(),
            &["authz.member_organizations"][..],
            "projects_capped",
            "Subquery reads the rows function 'authz.capped_kinds' returns",
        ),
        (
            POLICY_CAPS.to_string(),
            &["authz.member_organizations"][..],
            "reports_capped",
            "Subquery reads the rows function 'authz.capped_kinds' returns",
        ),
        (
            POLICY_CAPS.replace(
                star,
                "(organization_id, kind) NOT IN (SELECT * FROM authz.capped_kinds('writer'))",
            ),
            POLICY_CAP_HELPERS,
            "projects_capped",
            "NOT IN (subquery) cannot be represented as static OpenFGA membership tuples",
        ),
        (
            POLICY_CAPS.replacen(
                "kind authz.resource_kind NOT NULL\n);\nCREATE TABLE reports",
                "kind TEXT NOT NULL\n);\nCREATE TABLE reports",
                1,
            ),
            POLICY_CAP_HELPERS,
            "projects_capped",
            "the policy pairs column 'kind' of 'public.projects' with column 'kind' of the rows \
             'authz.capped_kinds' returns, and the two are not of one type",
        ),
        (
            POLICY_CAPS.replace(
                star,
                "('00000000-0000-0000-0000-000000000000'::uuid, 'project'::authz.resource_kind) \
                 IN (SELECT * FROM authz.capped_kinds('writer'))",
            ),
            POLICY_CAP_HELPERS,
            "projects_capped",
            "the policy pairs literals with the rows 'authz.capped_kinds' returns beside no \
             column of 'public.projects'",
        ),
        (
            POLICY_CAPS.replace(
                star,
                "(organization_id, 1::authz.resource_kind) \
                 IN (SELECT * FROM authz.capped_kinds('writer'))",
            ),
            POLICY_CAP_HELPERS,
            "projects_capped",
            "the policy pairs '1::authz.resource_kind' with the rows 'authz.capped_kinds' \
             returns, which is no literal a pair is named by",
        ),
        (
            POLICY_CAPS.replace(
                star,
                "(organization_id, kind, id) IN (SELECT * FROM authz.capped_kinds('writer'))",
            ),
            POLICY_CAP_HELPERS,
            "projects_capped",
            "Subquery reads the rows function 'authz.capped_kinds' returns",
        ),
        (
            POLICY_CAPS.replace(
                star,
                "(organization_id, projects.missing) IN (SELECT * FROM authz.capped_kinds('writer'))",
            ),
            POLICY_CAP_HELPERS,
            "projects_capped",
            "the policy pairs 'projects.missing' with the rows 'authz.capped_kinds' returns",
        ),
        (
            POLICY_CAPS.replace(
                star,
                "NOT ((organization_id, kind) IN (SELECT * FROM authz.capped_kinds('writer')))",
            ),
            POLICY_CAP_HELPERS,
            "projects_capped",
            "NOT applied to row among a declared helper's pairs",
        ),
        (
            POLICY_CAPS.replace(
                "ALTER FUNCTION authz.caller_id()",
                "CREATE FUNCTION authz.capped_kinds(min_role TEXT)\n\
                 RETURNS TABLE (organization_id UUID, kind authz.resource_kind)\n\
                 LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$\n  \
                 SELECT permission.organization_id, permission.kind\n  \
                 FROM public.installation_permissions permission\n$$;\n\
                 ALTER FUNCTION authz.caller_id()",
            ),
            POLICY_CAP_HELPERS,
            "projects_capped",
            "more than one declaration of 'authz.capped_kinds' takes this call's arguments",
        ),
    ] {
        let using = using_of(&schema, helpers, policy);
        assert_eq!(using.confidence, ConfidenceLevel::D, "{reason}");
        let refused = refusal_reasons(&using.pattern);
        assert!(
            refused.iter().any(|refused| refused.contains(reason)),
            "expected {reason}, got {refused:?}"
        );
    }
}

/// The reasons of every refused part of `pattern`.
fn refusal_reasons(pattern: &PatternClass) -> Vec<String> {
    match pattern {
        PatternClass::Unknown(UnclassifiedExpr { reason, .. }) => vec![reason.clone()],
        PatternClass::P8Composite(composite) => composite
            .parts
            .iter()
            .flat_map(|part| refusal_reasons(&part.pattern))
            .collect(),
        _ => Vec::new(),
    }
}
