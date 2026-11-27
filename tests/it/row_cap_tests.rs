//! Grant arms of a declared helper capped by the pairs another helper returns.

use rls2fga::classifier::patterns::{PatternClass, UnclassifiedExpr};
use rls2fga::translator::{Translator, TranslatorBuilder};
use rls2fga::types::{ConfidenceLevel, TranslationNote};
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

/// [`INSTALLATION_CAPS`] with `authz.member_organizations` capped by `authz.reader_kinds`,
/// which returns the installation's permissions meeting `condition`.
fn reader_kinds(condition: &str) -> String {
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
    .replace(
        "(SELECT * FROM authz.capped_kinds('reader'))",
        "(SELECT * FROM authz.reader_kinds())",
    )
}

/// [`INSTALLATION_CAPS`] with teams read through `authz.caller_grantees`, capped by
/// `authz.member_organizations`, whose own rows `authz.capped_kinds` caps. Where `blocked`,
/// `authz.capped_kinds` also leaves out the organizations blocking the caller.
pub(crate) fn nested_caps(blocked: bool) -> String {
    let exclusion = if blocked {
        "    AND NOT (permission.organization_id = ANY (ARRAY(SELECT authz.blocking_organizations())))\n"
    } else {
        ""
    };
    let capped = INSTALLATION_CAPS
        .replace(
            "CREATE FUNCTION authz.capped_kinds",
            "CREATE TABLE organization_blocks (
  organization_id UUID NOT NULL REFERENCES organizations (id),
  user_id UUID NOT NULL,
  PRIMARY KEY (organization_id, user_id)
);
GRANT SELECT ON organization_blocks TO authz_owner;
CREATE FUNCTION authz.blocking_organizations() RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT block.organization_id FROM public.organization_blocks block
  WHERE block.user_id = authz.caller_id()
$$;
ALTER FUNCTION authz.blocking_organizations() OWNER TO authz_owner;
CREATE FUNCTION authz.capped_kinds",
        )
        .replace(
            "    AND permission.max_role >= min_role\n",
            &format!("    AND permission.max_role >= min_role\n{exclusion}"),
        );
    format!(
        "{capped}CREATE TABLE teams (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES organizations (id)
);
CREATE TABLE team_members (
  team_id UUID NOT NULL REFERENCES teams (id),
  organization_id UUID NOT NULL REFERENCES organizations (id),
  user_id UUID NOT NULL,
  PRIMARY KEY (team_id, user_id)
);
ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON team_members TO authz_owner;
CREATE FUNCTION authz.caller_grantees() RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT member.team_id FROM public.team_members member
  WHERE member.user_id = authz.caller_id()
    AND member.organization_id IN (SELECT authz.member_organizations())
$$;
ALTER FUNCTION authz.caller_grantees() OWNER TO authz_owner;
CREATE POLICY teams_visible ON teams FOR SELECT
  USING (id IN (SELECT authz.caller_grantees()));
"
    )
}

pub(crate) const NESTED_CAP_HELPERS: &[&str] = &[
    "authz.capped_kinds",
    "authz.member_organizations",
    "authz.owned_resources",
    "authz.blocking_organizations",
    "authz.caller_grantees",
];

/// A cap whose own rows another cap keeps holds each of its pairs for the callers its rows
/// return the pair to only where the nested cap keeps that row, and the request gate lifting
/// the nested cap lifts it on the pair, whether the nested cap's rows stay outside a set or
/// not.
#[test]
fn a_cap_whose_own_rows_another_cap_keeps_translates() {
    for blocked in [false, true] {
        let schema = nested_caps(blocked);
        let using = using_of(&schema, NESTED_CAP_HELPERS, "teams_visible");
        assert_eq!(
            using.confidence,
            ConfidenceLevel::A,
            "blocked {blocked}: {:?}",
            using.pattern
        );
        let model = installation_translator(NESTED_CAP_HELPERS)
            .translate(&db_of(&schema))
            .expect("the schema plans")
            .outputs()
            .expect("the schema translates")
            .model();
        let pair = "member_organizations_pair";
        let held = relation_definition(&model, pair, "member_organizations")
            .unwrap_or_else(|| panic!("{pair} holds member_organizations in\n{model}"));
        let kept = relation_definition(&model, pair, &held)
            .unwrap_or_else(|| panic!("{pair} holds {held} in\n{model}"));
        let (granted, capped) = kept
            .split_once(" and ")
            .unwrap_or_else(|| panic!("{held} intersects the grant with the cap: {kept}"));
        assert_eq!(
            relation_definition(&model, pair, granted).as_deref(),
            Some("[user]"),
            "{held} intersects the members' grant with the cap: {kept}\n{model}"
        );
        let capped = capped
            .strip_prefix('(')
            .and_then(|capped| capped.strip_suffix(')'))
            .unwrap_or_else(|| panic!("{held} reads the cap or its lift: {kept}"));
        let (lifted, through) = capped
            .split_once(" or ")
            .unwrap_or_else(|| panic!("{held} lifts the cap: {capped}"));
        assert!(
            lifted.ends_with(" from request_gate"),
            "{held} lifts the cap on the request gate: {capped}\n{model}"
        );
        assert_eq!(
            through, "capped_kinds_reader from capped_kinds_reader_pair",
            "{model}"
        );
    }
}

/// [`nested_caps`] with each membership carrying the kind its organization is capped at,
/// which several memberships of one organization may differ in.
pub(crate) fn scoped_nested_caps() -> String {
    nested_caps(false)
        .replace(
            "  user_id UUID NOT NULL,\n  PRIMARY KEY (organization_id, user_id)\n);\n\
             CREATE TABLE app_installations",
            "  user_id UUID NOT NULL,\n  scope authz.resource_kind NOT NULL DEFAULT 'organization',\n  \
             PRIMARY KEY (organization_id, user_id)\n);\nCREATE TABLE app_installations",
        )
        .replace(
            "(membership.organization_id, 'organization'::authz.resource_kind)",
            "(membership.organization_id, membership.scope)",
        )
}

/// A nested cap reading more of a row than the pair it returns names holds the pair
/// through each of those rows, kept by the nested cap on its own.
#[test]
fn a_nested_cap_reading_more_than_its_pair_holds_the_pair_through_each_row() {
    let schema = scoped_nested_caps();
    let using = using_of(&schema, NESTED_CAP_HELPERS, "teams_visible");
    assert_eq!(using.confidence, ConfidenceLevel::A, "{:?}", using.pattern);
    let model = installation_translator(NESTED_CAP_HELPERS)
        .translate(&db_of(&schema))
        .expect("the schema plans")
        .outputs()
        .expect("the schema translates")
        .model();
    let pair = "member_organizations_pair";
    let held = relation_definition(&model, pair, "member_organizations")
        .unwrap_or_else(|| panic!("{pair} holds member_organizations in\n{model}"));
    let (rows, link) = held
        .split_once(" from ")
        .unwrap_or_else(|| panic!("{pair} holds its pairs through rows: {held}\n{model}"));
    assert_eq!(
        relation_definition(&model, pair, link).as_deref(),
        Some("[memberships]"),
        "{model}"
    );
    let kept = relation_definition(&model, "memberships", rows)
        .unwrap_or_else(|| panic!("memberships holds {rows} in\n{model}"));
    assert!(
        kept.contains("capped_kinds_reader from"),
        "each membership row meets the nested cap: {kept}\n{model}"
    );
}

/// A cap returning several columns, whose own rows another cap keeps by those columns,
/// grades A and translates.
#[test]
fn a_cap_of_several_columns_whose_rows_another_cap_keeps_translates() {
    let schema = reader_kinds(
        "(permission.organization_id, permission.kind) \
         IN (SELECT * FROM authz.capped_kinds('admin'))",
    );
    let helpers = [CAP_HELPERS, &["authz.reader_kinds"]].concat();
    let using = using_of(&schema, &helpers, "organizations_select");
    assert_eq!(using.confidence, ConfidenceLevel::A, "{:?}", using.pattern);
    installation_translator(&helpers)
        .translate(&db_of(&schema))
        .expect("the schema plans")
        .outputs()
        .expect("the schema translates");
}

/// A cap the model cannot keep is refused naming why, never dropped.
#[test]
fn caps_with_no_pair_relation_are_refused() {
    let lifted = "authz.acting_installation_id() IS NULL";
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
             'authz.installation_resources', which returns pairs through a parent or another \
             helper's rows",
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
        (
            format!(
                "{INSTALLATION_CAPS}CREATE TABLE kind_grants (
  organization_id UUID NOT NULL REFERENCES organizations (id),
  kind authz.resource_kind NOT NULL
);
GRANT SELECT ON kind_grants TO authz_owner;
CREATE FUNCTION authz.granted_kinds()
RETURNS TABLE (organization_id UUID, kind authz.resource_kind)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT kind_grant.organization_id, kind_grant.kind FROM public.kind_grants kind_grant
  WHERE (kind_grant.organization_id, 'organization'::authz.resource_kind)
    IN (SELECT * FROM authz.capped_kinds('admin'))
$$;
ALTER FUNCTION authz.granted_kinds() OWNER TO authz_owner;
"
            )
            .replace(
                "(SELECT * FROM authz.capped_kinds('reader'))",
                "(SELECT * FROM authz.granted_kinds())",
            ),
            "organizations_select",
            "declared helper 'authz.granted_kinds' pairs column 'organization_id' of \
             'public.kind_grants' with the rows 'authz.capped_kinds' returns, while several \
             rows of 'public.kind_grants' can return one row and no key names each of its rows",
        ),
    ] {
        let helpers = [
            CAP_HELPERS,
            JOINED_CAP_HELPERS,
            &[
                "authz.noted_organizations",
                "authz.reader_kinds",
                "authz.granted_kinds",
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
                "NOT ((organization_id, kind) IN (SELECT * FROM authz.capped_kinds('writer')))",
            ),
            POLICY_CAP_HELPERS,
            "projects_capped",
            "a blocklist exclusion requires a positive grant",
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
    let schema = POLICY_CAPS.replace(
        star,
        "(organization_id, projects.missing) IN (SELECT * FROM authz.capped_kinds('writer'))",
    );
    assert_eq!(
        crate::support::deployment::unknown_column(&schema),
        "projects.missing"
    );
}

/// [`POLICY_CAPS`] with `authz.capped_kinds` keeping only the permission rows whose
/// `compared` column stays outside the organizations blocking the caller.
pub(crate) fn blocked_caps(compared: &str) -> String {
    POLICY_CAPS
        .replace(
            "CREATE FUNCTION authz.capped_kinds",
            "CREATE TABLE organization_blocks (
  organization_id UUID NOT NULL REFERENCES organizations (id),
  user_id UUID NOT NULL,
  PRIMARY KEY (organization_id, user_id)
);
GRANT SELECT ON organization_blocks TO authz_owner;
CREATE FUNCTION authz.blocking_organizations() RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT block.organization_id FROM public.organization_blocks block
  WHERE block.user_id = authz.caller_id()
$$;
ALTER FUNCTION authz.blocking_organizations() OWNER TO authz_owner;
CREATE FUNCTION authz.capped_kinds",
        )
        .replace(
            "    AND permission.max_role >= min_role\n",
            &format!(
                "    AND permission.max_role >= min_role\n    \
                 AND NOT ({compared} = ANY (ARRAY(SELECT authz.blocking_organizations())))\n"
            ),
        )
}

pub(crate) const BLOCKED_CAP_HELPERS: &[&str] = &[
    "authz.capped_kinds",
    "authz.member_organizations",
    "authz.blocking_organizations",
];

/// Every row returning a pair holds the pair's organization, so each pair holds the
/// callers its rows return it to but not those its organization blocks.
#[test]
fn a_cap_excluding_a_set_on_a_pair_column_subtracts_it_from_each_pair() {
    let schema = blocked_caps("permission.organization_id");
    for policy in ["projects_capped", "reports_capped", "invitations_capped"] {
        let using = using_of(&schema, BLOCKED_CAP_HELPERS, policy);
        assert_eq!(
            using.confidence,
            ConfidenceLevel::A,
            "{policy}: {:?}",
            using.pattern
        );
    }
    let model = installation_translator(BLOCKED_CAP_HELPERS)
        .translate(&db_of(&schema))
        .expect("the schema plans")
        .outputs()
        .expect("the schema translates")
        .model();
    let pair = "capped_kinds_writer_pair";
    let held = relation_definition(&model, pair, "capped_kinds_writer")
        .unwrap_or_else(|| panic!("{pair} holds capped_kinds_writer in\n{model}"));
    let kept = relation_definition(&model, pair, &held)
        .unwrap_or_else(|| panic!("{pair} holds {held} in\n{model}"));
    let (_, link) = kept
        .split_once(" but not blocking_organizations from ")
        .unwrap_or_else(|| panic!("{held} subtracts the blocks: {kept}"));
    assert_eq!(
        relation_definition(&model, pair, link).as_deref(),
        Some("[organizations]"),
        "{model}"
    );
}

/// An exclusion compared on a column no pair carries, or one a `NULL` or an undeclared
/// helper keeps the model from stating, is refused naming why.
#[test]
fn cap_exclusions_the_pairs_cannot_carry_are_refused() {
    let blocked = blocked_caps("permission.organization_id");
    for (schema, helpers, reason) in [
        (
            blocked_caps("permission.installation_id"),
            BLOCKED_CAP_HELPERS,
            "declared helper 'authz.capped_kinds' keeps the rows of \
             'public.installation_permissions' only outside the set \
             'authz.blocking_organizations' returns",
        ),
        (
            blocked.replace(
                "  organization_id UUID NOT NULL REFERENCES organizations (id),\n  \
                 user_id UUID NOT NULL,\n  PRIMARY KEY (organization_id, user_id)",
                "  organization_id UUID REFERENCES organizations (id),\n  user_id UUID NOT NULL",
            ),
            BLOCKED_CAP_HELPERS,
            "organization_blocks.organization_id' must be provably non-null",
        ),
        (
            blocked,
            POLICY_CAP_HELPERS,
            "'authz.blocking_organizations', which is not declared",
        ),
    ] {
        let using = using_of(&schema, helpers, "projects_capped");
        assert_eq!(using.confidence, ConfidenceLevel::D, "{reason}");
        let refused = refusal_reasons(&using.pattern);
        assert!(
            refused.iter().any(|refused| refused.contains(reason)),
            "expected {reason}, got {refused:?}"
        );
    }
}

/// The pairs `capped_kinds('writer')` returns in `schema`, read on its pair type.
fn writer_pairs(schema: &str, helpers: &[&str]) -> Option<String> {
    let model = installation_translator(helpers)
        .translate(&db_of(schema))
        .expect("the schema plans")
        .outputs()
        .expect("the schema translates")
        .model();
    relation_definition(&model, "capped_kinds_writer_pair", "capped_kinds_writer")
}

/// `schema` declaring `authz.marking_organizations(marked)`, the organizations marking the
/// caller as `marked`, which returns no row for a mark the `CHECK` refuses.
fn with_marks(schema: &str) -> String {
    schema.replace(
        "CREATE FUNCTION authz.capped_kinds",
        "CREATE TABLE organization_marks (
  organization_id UUID NOT NULL REFERENCES organizations (id),
  user_id UUID NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('block', 'mute')),
  PRIMARY KEY (organization_id, user_id, kind)
);
GRANT SELECT ON organization_marks TO authz_owner;
CREATE FUNCTION authz.marking_organizations(marked TEXT) RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT mark.organization_id FROM public.organization_marks mark
  WHERE mark.user_id = authz.caller_id() AND mark.kind = marked
$$;
ALTER FUNCTION authz.marking_organizations(TEXT) OWNER TO authz_owner;
CREATE FUNCTION authz.capped_kinds",
    )
}

const MARKING_CAP_HELPERS: &[&str] = &[
    "authz.capped_kinds",
    "authz.member_organizations",
    "authz.blocking_organizations",
    "authz.marking_organizations",
];

/// `NOT (x = ANY ('{}'))` holds for every `x`, so a set returning no row takes no pair away.
#[test]
fn a_cap_excluding_a_set_returning_no_row_keeps_every_pair() {
    let banned = with_marks(&blocked_caps("permission.organization_id")).replace(
        "ARRAY(SELECT authz.blocking_organizations())",
        "ARRAY(SELECT authz.marking_organizations('ban'))",
    );
    let kept = writer_pairs(&banned, MARKING_CAP_HELPERS);
    assert!(kept.is_some(), "{banned}");
    assert_eq!(kept, writer_pairs(POLICY_CAPS, POLICY_CAP_HELPERS));
}

pub(crate) const PERSONAL_RESOURCES: &str = "
CREATE TABLE resource_notes (
  id UUID PRIMARY KEY,
  resource_id UUID NOT NULL REFERENCES resources (id)
);
ALTER TABLE resource_notes ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION authz.personal_resources() RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT resource.id FROM public.resources resource
  WHERE resource.owner_id = authz.caller_id() AND authz.acting_installation_id() IS NULL
$$;
ALTER FUNCTION authz.personal_resources() OWNER TO authz_owner;
CREATE POLICY resource_notes_select ON resource_notes FOR SELECT
  USING (resource_id IN (SELECT authz.personal_resources()));
";

/// The helpers [`INSTALLATION_CAPS`] and [`PERSONAL_RESOURCES`] declare.
pub(crate) const PERSONAL_HELPERS: &[&str] = &[
    "authz.capped_kinds",
    "authz.member_organizations",
    "authz.owned_resources",
    "authz.personal_resources",
];

/// A grant arm kept only while the request leaves a setting unset grades A and gates its
/// rows on the request omitting that setting.
#[test]
fn an_arm_kept_while_a_setting_is_unset_translates() {
    let schema = format!("{INSTALLATION_CAPS}{PERSONAL_RESOURCES}");
    let using = using_of(&schema, PERSONAL_HELPERS, "resource_notes_select");
    assert_eq!(using.confidence, ConfidenceLevel::A, "{:?}", using.pattern);
    let translation = installation_translator(PERSONAL_HELPERS)
        .translate(&db_of(&schema))
        .expect("the schema plans");
    let model = translation
        .outputs()
        .expect("the schema translates")
        .model();
    let personal = relation_definition(&model, "resources", "personal_resources")
        .unwrap_or_else(|| panic!("resources holds personal_resources in\n{model}"));
    let gated = relation_definition(&model, "resources", &personal)
        .unwrap_or_else(|| panic!("resources holds {personal} in\n{model}"));
    assert!(
        gated.contains(" and app_installation_id_absent"),
        "{personal}: {gated}"
    );
}

/// An arm kept while a setting is unset, read where the request's absence does not decide
/// the setting, is refused naming why.
#[test]
fn arms_kept_while_a_setting_is_unset_are_refused_where_the_model_cannot_gate_them() {
    let unset = "authz.acting_installation_id() IS NULL";
    let personal = format!("{INSTALLATION_CAPS}{PERSONAL_RESOURCES}");
    let kept = "declared helper 'authz.personal_resources' keeps an arm's rows only where \
                setting";
    for (schema, policy, reason) in [
        (
            personal.replace(
                unset,
                "current_setting('app.installation_id', true)::uuid IS NULL",
            ),
            "resource_notes_select",
            format!(
                "{kept} 'app.installation_id' reads NULL, but reads it without NULLIF(..., '')"
            ),
        ),
        (
            personal.replace(
                unset,
                "NULLIF(current_setting('app.installation_id'), '')::uuid IS NULL",
            ),
            "resource_notes_select",
            format!(
                "{kept} 'app.installation_id' reads NULL, but reads it through current_setting \
                 without missing_ok, which raises 42704"
            ),
        ),
        (
            personal.replace(
                unset,
                "NULLIF(current_setting('app.user_id', true), '')::uuid IS NULL",
            ),
            "resource_notes_select",
            format!(
                "{kept} 'app.user_id' reads NULL, which the deployment does not declare as one \
                 value a request may leave unset"
            ),
        ),
    ] {
        let using = using_of(&schema, PERSONAL_HELPERS, policy);
        assert_eq!(using.confidence, ConfidenceLevel::D, "{reason}");
        match using.pattern {
            PatternClass::Unknown(UnclassifiedExpr {
                reason: refused, ..
            }) => assert!(
                refused.contains(&reason),
                "expected {reason}, got {refused}"
            ),
            other => panic!("{policy} should be refused with {reason}, got {other:?}"),
        }
    }
}

pub(crate) const FOUNDED_PAIRS: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE organizations (
  namespace_id UUID NOT NULL, id UUID NOT NULL, created_by_id UUID NOT NULL,
  founded_at TIMESTAMPTZ, PRIMARY KEY (namespace_id, id)
);
CREATE TABLE organization_notes (
  id UUID PRIMARY KEY, organization_namespace_id UUID NOT NULL, organization_id UUID NOT NULL,
  FOREIGN KEY (organization_namespace_id, organization_id)
    REFERENCES organizations (namespace_id, id)
);
ALTER TABLE organization_notes ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON organizations TO authz_owner;
CREATE FUNCTION authz.caller_id() RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT NULLIF(current_setting('app.user_id', true), '')::uuid
$$;
CREATE FUNCTION authz.acting_installation_id() RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT NULLIF(current_setting('app.installation_id', true), '')::uuid
$$;
CREATE FUNCTION authz.founded_organizations() RETURNS TABLE (namespace_id UUID, id UUID)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT organization.namespace_id, organization.id FROM public.organizations organization
  WHERE organization.created_by_id = (SELECT authz.caller_id())
    AND organization.founded_at IS NULL
    AND (SELECT authz.acting_installation_id()) IS NULL
$$;
ALTER FUNCTION authz.caller_id() OWNER TO authz_owner;
ALTER FUNCTION authz.acting_installation_id() OWNER TO authz_owner;
ALTER FUNCTION authz.founded_organizations() OWNER TO authz_owner;
CREATE POLICY organization_notes_founded ON organization_notes FOR SELECT
  USING ((organization_namespace_id, organization_id)
    IN (SELECT * FROM authz.founded_organizations()));
";

pub(crate) const FOUNDED_HELPERS: &[&str] = &["authz.founded_organizations"];

/// A row compared with the pairs of a helper whose arm keeps its rows only while no
/// installation acts reaches pairs gated on the installation's absence.
#[test]
fn a_pair_membership_kept_while_a_setting_is_unset_gates_its_pairs() {
    let using = using_of(FOUNDED_PAIRS, FOUNDED_HELPERS, "organization_notes_founded");
    assert_eq!(using.confidence, ConfidenceLevel::A, "{:?}", using.pattern);
    let model = installation_translator(FOUNDED_HELPERS)
        .translate(&db_of(FOUNDED_PAIRS))
        .expect("the schema plans")
        .outputs()
        .expect("the schema translates")
        .model();
    let pair = "founded_organizations_pair";
    let held = relation_definition(&model, pair, "founded_organizations")
        .unwrap_or_else(|| panic!("{pair} holds founded_organizations in\n{model}"));
    let gated = relation_definition(&model, pair, &held)
        .unwrap_or_else(|| panic!("{pair} holds {held} in\n{model}"));
    assert!(
        gated.contains(" and app_installation_id_absent"),
        "{held}: {gated}"
    );
}

/// A pair arm kept while a setting is unset, read where the request's absence does not
/// decide the setting, is refused naming why.
#[test]
fn a_pair_arm_kept_while_a_setting_reads_bare_is_refused() {
    let schema = FOUNDED_PAIRS.replace(
        "(SELECT authz.acting_installation_id()) IS NULL",
        "current_setting('app.installation_id', true)::uuid IS NULL",
    );
    let using = using_of(&schema, FOUNDED_HELPERS, "organization_notes_founded");
    assert_eq!(using.confidence, ConfidenceLevel::D, "{:?}", using.pattern);
    let reason = "declared helper 'authz.founded_organizations' keeps an arm's rows only where \
                  setting 'app.installation_id' reads NULL, but reads it without NULLIF(..., '')";
    let refused = refusal_reasons(&using.pattern);
    assert!(
        refused.iter().any(|refused| refused.contains(reason)),
        "expected {reason}, got {refused:?}"
    );
}

pub(crate) const ADMINISTERED_TEAMS: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE organizations (namespace_id UUID NOT NULL, id UUID NOT NULL,
  PRIMARY KEY (namespace_id, id));
CREATE TABLE memberships (
  organization_namespace_id UUID NOT NULL, organization_id UUID NOT NULL,
  user_namespace_id UUID NOT NULL, user_id UUID NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('active', 'deactivated')),
  PRIMARY KEY (organization_namespace_id, organization_id, user_namespace_id, user_id),
  FOREIGN KEY (organization_namespace_id, organization_id)
    REFERENCES organizations (namespace_id, id)
);
CREATE TABLE teams (
  namespace_id UUID NOT NULL, id UUID NOT NULL,
  organization_namespace_id UUID NOT NULL, organization_id UUID NOT NULL,
  PRIMARY KEY (namespace_id, id),
  FOREIGN KEY (organization_namespace_id, organization_id)
    REFERENCES organizations (namespace_id, id)
);
CREATE TABLE team_members (
  team_namespace_id UUID NOT NULL, team_id UUID NOT NULL,
  organization_namespace_id UUID NOT NULL, organization_id UUID NOT NULL,
  user_namespace_id UUID NOT NULL, user_id UUID NOT NULL,
  team_role TEXT NOT NULL CHECK (team_role IN ('admin', 'member')),
  PRIMARY KEY (team_namespace_id, team_id, user_namespace_id, user_id),
  FOREIGN KEY (team_namespace_id, team_id) REFERENCES teams (namespace_id, id),
  FOREIGN KEY (organization_namespace_id, organization_id, user_namespace_id, user_id)
    REFERENCES memberships (organization_namespace_id, organization_id, user_namespace_id, user_id)
);
CREATE TABLE team_notes (
  id UUID PRIMARY KEY, team_namespace_id UUID NOT NULL, team_id UUID NOT NULL,
  FOREIGN KEY (team_namespace_id, team_id) REFERENCES teams (namespace_id, id)
);
ALTER TABLE team_notes ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON memberships, team_members TO authz_owner;
CREATE FUNCTION authz.caller_id() RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT NULLIF(current_setting('app.user_id', true), '')::uuid
$$;
CREATE FUNCTION authz.administered_teams() RETURNS TABLE (namespace_id UUID, id UUID)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT member.team_namespace_id, member.team_id FROM public.team_members member
  JOIN public.memberships membership
    ON membership.organization_namespace_id = member.organization_namespace_id
      AND membership.organization_id = member.organization_id
      AND membership.user_namespace_id = member.user_namespace_id
      AND membership.user_id = member.user_id
  WHERE member.user_namespace_id = '0a000000-0000-4000-8000-000000000001'
    AND member.user_id = (SELECT authz.caller_id())
    AND member.team_role = 'admin' AND membership.state = 'active'
$$;
ALTER FUNCTION authz.caller_id() OWNER TO authz_owner;
ALTER FUNCTION authz.administered_teams() OWNER TO authz_owner;
CREATE POLICY team_notes_administered ON team_notes FOR SELECT
  USING ((team_namespace_id, team_id) IN (SELECT * FROM authz.administered_teams()));
";

pub(crate) const ADMINISTERED_HELPERS: &[&str] = &["authz.administered_teams"];

/// An arm returning pairs from the rows that name a joined row meeting the join holds each
/// of its rows as its own object, which holds the grant while its joined row meets the
/// join, and each pair links to the rows returning it.
#[test]
fn a_joined_arm_returning_pairs_holds_them_through_its_rows() {
    let using = using_of(
        ADMINISTERED_TEAMS,
        ADMINISTERED_HELPERS,
        "team_notes_administered",
    );
    assert_eq!(using.confidence, ConfidenceLevel::A, "{:?}", using.pattern);
    let model = installation_translator(ADMINISTERED_HELPERS)
        .translate(&db_of(ADMINISTERED_TEAMS))
        .expect("the schema plans")
        .outputs()
        .expect("the schema translates")
        .model();
    assert_eq!(
        relation_definition(&model, "administered_teams_pair", "administered_teams").as_deref(),
        Some("team_members_with_memberships from team_members"),
        "{model}"
    );
    let held = relation_definition(&model, "team_members", "team_members_with_memberships")
        .unwrap_or_else(|| panic!("team_members holds its joined grant in\n{model}"));
    assert!(held.ends_with(" from memberships"), "{held}");
}

pub(crate) const PAIR_WALK: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE grantees (
  namespace_id UUID NOT NULL, id UUID NOT NULL, kind TEXT NOT NULL,
  PRIMARY KEY (namespace_id, id)
);
CREATE TABLE teams (
  namespace_id UUID NOT NULL, id UUID NOT NULL, PRIMARY KEY (namespace_id, id),
  FOREIGN KEY (namespace_id, id) REFERENCES grantees (namespace_id, id)
);
CREATE TABLE team_members (
  team_namespace_id UUID NOT NULL, team_id UUID NOT NULL,
  user_namespace_id UUID NOT NULL, user_id UUID NOT NULL,
  PRIMARY KEY (team_namespace_id, team_id, user_namespace_id, user_id),
  FOREIGN KEY (team_namespace_id, team_id) REFERENCES teams (namespace_id, id),
  FOREIGN KEY (user_namespace_id, user_id) REFERENCES grantees (namespace_id, id)
);
CREATE TABLE team_parents (
  child_namespace_id UUID NOT NULL, child_id UUID NOT NULL,
  parent_namespace_id UUID NOT NULL, parent_id UUID NOT NULL,
  expires_at TIMESTAMPTZ,
  PRIMARY KEY (child_namespace_id, child_id),
  FOREIGN KEY (child_namespace_id, child_id) REFERENCES teams (namespace_id, id),
  FOREIGN KEY (parent_namespace_id, parent_id) REFERENCES teams (namespace_id, id)
);
CREATE TABLE resources (id UUID PRIMARY KEY);
CREATE TABLE team_notes (id UUID PRIMARY KEY, team_id UUID NOT NULL);
CREATE TABLE grants (
  resource_id UUID NOT NULL REFERENCES resources (id),
  grantee_namespace_id UUID NOT NULL, grantee_id UUID NOT NULL,
  PRIMARY KEY (resource_id, grantee_namespace_id, grantee_id),
  FOREIGN KEY (grantee_namespace_id, grantee_id) REFERENCES grantees (namespace_id, id)
);
GRANT SELECT ON grantees, teams, team_members, team_parents, grants TO authz_owner;
CREATE FUNCTION authz.caller_id() RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT NULLIF(current_setting('app.user_id', true), '')::uuid
$$;
CREATE FUNCTION authz.caller_grantees() RETURNS TABLE (namespace_id UUID, id UUID)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH RECURSIVE reached (namespace_id, id) AS (
    SELECT grantee.namespace_id, grantee.id FROM public.grantees grantee
    WHERE grantee.id = (SELECT authz.caller_id()) AND grantee.kind = 'user'
    UNION
    SELECT member.team_namespace_id, member.team_id FROM public.team_members member
    WHERE member.user_id = (SELECT authz.caller_id())
    UNION
    SELECT parent.parent_namespace_id, parent.parent_id FROM public.team_parents parent
    JOIN reached ON (parent.child_namespace_id, parent.child_id) = (reached.namespace_id, reached.id)
  )
  SELECT reached.namespace_id, reached.id FROM reached
$$;
CREATE FUNCTION authz.granted_resources() RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT permission.resource_id FROM public.grants permission
  WHERE (permission.grantee_namespace_id, permission.grantee_id)
    IN (SELECT * FROM authz.caller_grantees())
$$;
ALTER FUNCTION authz.caller_id() OWNER TO authz_owner;
ALTER FUNCTION authz.caller_grantees() OWNER TO authz_owner;
ALTER FUNCTION authz.granted_resources() OWNER TO authz_owner;
ALTER TABLE grantees ENABLE ROW LEVEL SECURITY;
CREATE POLICY grantees_select ON grantees FOR SELECT
  USING ((namespace_id, id) IN (SELECT * FROM authz.caller_grantees()));
ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
CREATE POLICY resources_select ON resources FOR SELECT
  USING (id IN (SELECT authz.granted_resources()));
ALTER TABLE team_notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY team_notes_select ON team_notes FOR SELECT
  USING (('0a000000-0000-4000-8000-000000000001'::uuid, team_id)
    IN (SELECT * FROM authz.caller_grantees()));
";

pub(crate) const PAIR_WALK_HELPERS: &[&str] = &["authz.caller_grantees", "authz.granted_resources"];

const PAIR_WALK_UP: &str = "SELECT parent.parent_namespace_id, parent.parent_id \
     FROM public.team_parents parent
    JOIN reached ON (parent.child_namespace_id, parent.child_id) = (reached.namespace_id, reached.id)";

/// [`PAIR_WALK`] with the recursive term walking up replaced by `term`.
pub(crate) fn pair_walk(term: &str) -> String {
    assert!(
        PAIR_WALK.contains(PAIR_WALK_UP),
        "the term to replace is written"
    );
    PAIR_WALK.replace(PAIR_WALK_UP, term)
}

/// The caller, which [`PAIR_WALK`] reads through `authz.caller_id()`.
fn pair_walk_translator() -> Translator {
    TranslatorBuilder::new(deployment([typed_caller("app.user_id", DataType::Uuid)]))
        .with_min_confidence(ConfidenceLevel::B)
        .with_declared_helpers(PAIR_WALK_HELPERS.iter().copied())
        .build()
}

/// A helper walking teams by their namespace and id, up or down, compared as rows or column
/// by column, and following only the edges still live, is read by the policies comparing a
/// row, or a literal beside a column, with its pairs and by the cap a grant arm compares
/// with them.
#[test]
fn a_walk_over_pairs_keyed_by_two_columns_translates() {
    let down = "SELECT parent.child_namespace_id, parent.child_id FROM public.team_parents parent
    JOIN reached ON (parent.parent_namespace_id, parent.parent_id) = (reached.namespace_id, reached.id)";
    let columnwise = "SELECT parent.parent_namespace_id, parent.parent_id \
     FROM public.team_parents parent
    JOIN reached ON parent.child_namespace_id = reached.namespace_id \
     AND parent.child_id = reached.id";
    let live = "SELECT parent.parent_namespace_id, parent.parent_id FROM public.team_parents parent
    JOIN reached ON (parent.child_namespace_id, parent.child_id) = (reached.namespace_id, reached.id)
    WHERE parent.expires_at IS NULL OR parent.expires_at > now()";
    for schema in [
        PAIR_WALK.to_string(),
        pair_walk(down),
        pair_walk(columnwise),
        pair_walk(live),
    ] {
        let outputs = pair_walk_translator()
            .translate(&db_of(&schema))
            .expect("the schema plans")
            .outputs()
            .expect("the schema translates");
        let report = outputs.report();
        assert!(
            report.contains("P30 ((namespace_id, id) in authz.caller_grantees())"),
            "{report}"
        );
        let walks: Vec<Vec<String>> = outputs
            .notes()
            .iter()
            .filter_map(|note| match note {
                TranslationNote::HelperWalkDepth {
                    function, columns, ..
                } if function == "authz.caller_grantees" => {
                    Some(columns.iter().map(ToString::to_string).collect())
                }
                _ => None,
            })
            .collect();
        assert!(!walks.is_empty(), "{schema}");
        for columns in walks {
            assert_eq!(columns.len(), 2, "{columns:?}");
        }
        for policy in ["grantees_select", "resources_select", "team_notes_select"] {
            let using = pair_walk_translator()
                .classify(&db_of(&schema))
                .into_iter()
                .find(|classified| classified.name() == policy)
                .unwrap_or_else(|| panic!("{policy} should classify"))
                .using_classification()
                .unwrap_or_else(|| panic!("{policy} USING should classify"))
                .clone();
            assert_eq!(
                using.confidence,
                ConfidenceLevel::A,
                "{policy}: {:?}",
                using.pattern
            );
        }
    }
}

/// A walk over pairs reaches only pairs its seed returns, so a seed keeping a kind the
/// `CHECK` refuses returns no pair and the policy comparing a row with them denies.
#[test]
fn a_walk_over_pairs_from_a_seed_returning_nothing_denies() {
    let seed = "WHERE grantee.id = (SELECT authz.caller_id()) AND grantee.kind = 'user'
    UNION
    SELECT member.team_namespace_id, member.team_id FROM public.team_members member
    WHERE member.user_id = (SELECT authz.caller_id())
    UNION";
    assert!(PAIR_WALK.contains(seed), "the seed to replace is written");
    let schema = PAIR_WALK
        .replace(
            "kind TEXT NOT NULL,",
            "kind TEXT NOT NULL CHECK (kind IN ('user', 'team')),",
        )
        .replace(
            seed,
            "WHERE grantee.id = (SELECT authz.caller_id()) AND grantee.kind = 'robot'
    UNION",
        );
    let model = pair_walk_translator()
        .translate(&db_of(&schema))
        .expect("the schema plans")
        .outputs()
        .expect("the schema translates")
        .model();
    assert_eq!(
        relation_definition(&model, "grantees", "can_select").as_deref(),
        Some("no_access and acting_app_user from request_gate"),
        "{model}"
    );
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
