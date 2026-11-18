-- The core schema of connetto-rs/connetto-schema, pinned at commit 0b6c025 on the
-- add-core-schema branch: cluster/roles.sql and sql/*/up.sql concatenated in name
-- order, as the lint crate applies them. Refreshing the fixture is copying those files
-- again from the pinned commit.
CREATE ROLE app NOLOGIN;
CREATE ROLE identity_writer NOLOGIN;
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE ROLE authz_writer NOLOGIN BYPASSRLS;


CREATE SCHEMA authz;
REVOKE ALL ON SCHEMA authz FROM PUBLIC;
GRANT USAGE ON SCHEMA authz TO app, authz_owner;

CREATE TYPE authz.role AS ENUM ('reader', 'writer', 'admin');
CREATE TYPE authz.resource_kind AS ENUM ('organization', 'folder', 'project', 'ownable');
CREATE TYPE authz.grantee_kind AS ENUM ('user', 'installation', 'team', 'organization', 'everyone', 'signed_in', 'link');
CREATE TYPE authz.membership_state AS ENUM ('active', 'deactivated');
CREATE TYPE authz.team_role AS ENUM ('member', 'admin');
CREATE TYPE authz.audit_operation AS ENUM ('INSERT', 'UPDATE', 'DELETE');

CREATE TABLE grantees (
  id UUID PRIMARY KEY,
  kind authz.grantee_kind NOT NULL,
  UNIQUE (id, kind)
);
ALTER TABLE grantees ENABLE ROW LEVEL SECURITY;
ALTER TABLE grantees FORCE ROW LEVEL SECURITY;

CREATE UNIQUE INDEX ON grantees (kind) WHERE kind IN ('everyone', 'signed_in');
INSERT INTO grantees (id, kind) VALUES
  (gen_random_uuid(), 'everyone'), (gen_random_uuid(), 'signed_in');

CREATE TABLE users (
  id UUID PRIMARY KEY,
  kind authz.grantee_kind GENERATED ALWAYS AS ('user'::authz.grantee_kind) STORED NOT NULL,
  FOREIGN KEY (id, kind) REFERENCES grantees (id, kind) DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;

CREATE TABLE platform_operators (
  id UUID PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE
);
ALTER TABLE platform_operators ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_operators FORCE ROW LEVEL SECURITY;

CREATE TABLE organizations (
  id UUID PRIMARY KEY,
  kind authz.grantee_kind GENERATED ALWAYS AS ('organization'::authz.grantee_kind) STORED NOT NULL,
  created_by_id UUID NOT NULL REFERENCES users (id),
  -- Set by the first admin grant on the organization. Its creator takes the founding membership and grant only while it is NULL.
  founded_at TIMESTAMPTZ,
  FOREIGN KEY (id, kind) REFERENCES grantees (id, kind) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX ON organizations (created_by_id);
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;

CREATE TABLE invitations (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES organizations (id),
  email TEXT NOT NULL CHECK (email <> '' AND length(email) <= 320 AND email LIKE '%_@_%' AND email = lower(email)),
  expires_at TIMESTAMPTZ NOT NULL,
  invited_by_id UUID NOT NULL REFERENCES users (id),
  accepted_by_id UUID REFERENCES users (id),
  UNIQUE (organization_id, id)
);
CREATE INDEX ON invitations (invited_by_id);
CREATE INDEX ON invitations (accepted_by_id);
CREATE INDEX ON invitations (email);
ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations FORCE ROW LEVEL SECURITY;

CREATE TABLE memberships (
  organization_id UUID NOT NULL REFERENCES organizations (id),
  user_id UUID NOT NULL REFERENCES users (id),
  state authz.membership_state NOT NULL,
  invitation_id UUID UNIQUE,
  PRIMARY KEY (organization_id, user_id),
  FOREIGN KEY (organization_id, invitation_id) REFERENCES invitations (organization_id, id)
);
CREATE INDEX ON memberships (user_id);
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships FORCE ROW LEVEL SECURITY;

CREATE TABLE teams (
  id UUID PRIMARY KEY,
  kind authz.grantee_kind GENERATED ALWAYS AS ('team'::authz.grantee_kind) STORED NOT NULL,
  organization_id UUID NOT NULL REFERENCES organizations (id),
  UNIQUE (organization_id, id),
  FOREIGN KEY (id, kind) REFERENCES grantees (id, kind) DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE teams FORCE ROW LEVEL SECURITY;

CREATE TABLE team_parents (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL,
  parent_id UUID NOT NULL CHECK (parent_id <> id),
  FOREIGN KEY (organization_id, id) REFERENCES teams (organization_id, id),
  FOREIGN KEY (organization_id, parent_id) REFERENCES teams (organization_id, id)
);
CREATE INDEX ON team_parents (parent_id);
ALTER TABLE team_parents ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_parents FORCE ROW LEVEL SECURITY;

CREATE TABLE team_members (
  team_id UUID NOT NULL,
  organization_id UUID NOT NULL,
  user_id UUID NOT NULL,
  team_role authz.team_role NOT NULL,
  PRIMARY KEY (team_id, user_id),
  FOREIGN KEY (organization_id, team_id) REFERENCES teams (organization_id, id),
  FOREIGN KEY (organization_id, user_id) REFERENCES memberships (organization_id, user_id) ON DELETE CASCADE
);
CREATE INDEX ON team_members (user_id, organization_id);
ALTER TABLE team_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_members FORCE ROW LEVEL SECURITY;

CREATE TABLE resources (
  id UUID PRIMARY KEY,
  kind authz.resource_kind NOT NULL,
  organization_id UUID NOT NULL REFERENCES organizations (id),
  archived_at TIMESTAMPTZ,
  writers_can_share BOOLEAN NOT NULL DEFAULT FALSE,
  UNIQUE (id, kind),
  UNIQUE (organization_id, id),
  CHECK ((kind = 'organization') = (id = organization_id))
);
ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE resources FORCE ROW LEVEL SECURITY;

CREATE TABLE resource_parents (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL,
  resource_kind authz.resource_kind NOT NULL CHECK (resource_kind IN ('folder', 'project')),
  parent_id UUID NOT NULL CHECK (parent_id <> id),
  parent_kind authz.resource_kind NOT NULL CHECK (parent_kind IN ('organization', 'folder')),
  FOREIGN KEY (organization_id, id) REFERENCES resources (organization_id, id),
  FOREIGN KEY (organization_id, parent_id) REFERENCES resources (organization_id, id),
  FOREIGN KEY (id, resource_kind) REFERENCES resources (id, kind),
  FOREIGN KEY (parent_id, parent_kind) REFERENCES resources (id, kind)
);
CREATE INDEX ON resource_parents (parent_id);
ALTER TABLE resource_parents ENABLE ROW LEVEL SECURITY;
ALTER TABLE resource_parents FORCE ROW LEVEL SECURITY;

CREATE TABLE ownables (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL,
  kind authz.resource_kind GENERATED ALWAYS AS ('ownable'::authz.resource_kind) STORED NOT NULL,
  project_id UUID NOT NULL,
  project_kind authz.resource_kind GENERATED ALWAYS AS ('project'::authz.resource_kind) STORED NOT NULL,
  created_by_id UUID NOT NULL REFERENCES users (id),
  UNIQUE (id, project_id),
  FOREIGN KEY (id, kind) REFERENCES resources (id, kind) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (organization_id, id) REFERENCES resources (organization_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (project_id, project_kind) REFERENCES resources (id, kind),
  FOREIGN KEY (organization_id, project_id) REFERENCES resources (organization_id, id)
);
CREATE INDEX ON ownables (project_id);
CREATE INDEX ON ownables (created_by_id);
ALTER TABLE ownables ENABLE ROW LEVEL SECURITY;
ALTER TABLE ownables FORCE ROW LEVEL SECURITY;

CREATE TABLE grants (
  resource_id UUID NOT NULL,
  organization_id UUID NOT NULL,
  grantee_id UUID NOT NULL,
  grantee_kind authz.grantee_kind NOT NULL,
  role authz.role NOT NULL,
  expires_at TIMESTAMPTZ,
  PRIMARY KEY (resource_id, grantee_id),
  FOREIGN KEY (organization_id, resource_id) REFERENCES resources (organization_id, id),
  FOREIGN KEY (grantee_id, grantee_kind) REFERENCES grantees (id, kind) ON DELETE CASCADE,
  CHECK (grantee_kind NOT IN ('everyone', 'signed_in', 'link') OR role < 'admin')
);
CREATE INDEX ON grants (grantee_id);
ALTER TABLE grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE grants FORCE ROW LEVEL SECURITY;

CREATE TABLE share_links (
  id UUID PRIMARY KEY,
  kind authz.grantee_kind GENERATED ALWAYS AS ('link'::authz.grantee_kind) STORED NOT NULL,
  organization_id UUID NOT NULL REFERENCES organizations (id),
  token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_by_id UUID NOT NULL REFERENCES users (id),
  FOREIGN KEY (id, kind) REFERENCES grantees (id, kind) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX ON share_links (organization_id);
CREATE INDEX ON share_links (created_by_id);
ALTER TABLE share_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE share_links FORCE ROW LEVEL SECURITY;

CREATE TABLE organization_blocks (
  organization_id UUID NOT NULL REFERENCES organizations (id),
  principal_id UUID NOT NULL,
  principal_kind authz.grantee_kind NOT NULL CHECK (principal_kind IN ('user', 'installation')),
  expires_at TIMESTAMPTZ,
  PRIMARY KEY (organization_id, principal_id),
  FOREIGN KEY (principal_id, principal_kind) REFERENCES grantees (id, kind) ON DELETE CASCADE
);
CREATE INDEX ON organization_blocks (principal_id);
ALTER TABLE organization_blocks ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_blocks FORCE ROW LEVEL SECURITY;

CREATE TABLE apps (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES organizations (id),
  name TEXT NOT NULL CHECK (name <> '' AND length(name) <= 200)
);
CREATE INDEX ON apps (organization_id);
ALTER TABLE apps ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps FORCE ROW LEVEL SECURITY;

CREATE TABLE app_installations (
  id UUID PRIMARY KEY,
  kind authz.grantee_kind GENERATED ALWAYS AS ('installation'::authz.grantee_kind) STORED NOT NULL,
  app_id UUID NOT NULL REFERENCES apps (id),
  organization_id UUID NOT NULL REFERENCES organizations (id),
  UNIQUE (organization_id, id),
  FOREIGN KEY (id, kind) REFERENCES grantees (id, kind) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX ON app_installations (app_id);
ALTER TABLE app_installations ENABLE ROW LEVEL SECURITY;
ALTER TABLE app_installations FORCE ROW LEVEL SECURITY;

CREATE TABLE installation_permissions (
  installation_id UUID NOT NULL,
  organization_id UUID NOT NULL,
  kind authz.resource_kind NOT NULL,
  max_role authz.role NOT NULL,
  PRIMARY KEY (installation_id, kind),
  FOREIGN KEY (organization_id, installation_id) REFERENCES app_installations (organization_id, id)
);
ALTER TABLE installation_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE installation_permissions FORCE ROW LEVEL SECURITY;

-- No foreign keys, so the record outlives the rows, principals and organizations it names.
CREATE TABLE audit_events (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  at TIMESTAMPTZ NOT NULL,
  organization_id UUID NOT NULL,
  actor_id UUID,
  original_actor_id UUID,
  installation_id UUID,
  table_name TEXT NOT NULL CHECK (table_name <> '' AND length(table_name) <= 63),
  operation authz.audit_operation NOT NULL,
  old_row JSONB,
  new_row JSONB,
  CHECK ((operation = 'INSERT') = (old_row IS NULL) AND (operation = 'DELETE') = (new_row IS NULL))
);
CREATE INDEX ON audit_events (organization_id, at);
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;

-- Changes to users, organizations and platform operators, which no organization can hold, since deleting an organization removes its admins.
CREATE TABLE platform_audit_events (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  at TIMESTAMPTZ NOT NULL,
  actor_id UUID,
  original_actor_id UUID,
  installation_id UUID,
  table_name TEXT NOT NULL CHECK (table_name <> '' AND length(table_name) <= 63),
  operation authz.audit_operation NOT NULL,
  old_row JSONB,
  new_row JSONB,
  CHECK ((operation = 'INSERT') = (old_row IS NULL) AND (operation = 'DELETE') = (new_row IS NULL))
);
CREATE INDEX ON platform_audit_events (at);
ALTER TABLE platform_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_audit_events FORCE ROW LEVEL SECURITY;

ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE authz_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

GRANT SELECT ON grantees, platform_operators, organizations, memberships, invitations, teams, team_members, team_parents,
  share_links, resources, resource_parents, ownables, grants, organization_blocks, installation_permissions TO authz_owner;

CREATE FUNCTION authz.caller_id() RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT NULLIF(current_setting('app.user_id', true), '')::uuid
$$;

CREATE FUNCTION authz.acting_installation_id() RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT NULLIF(current_setting('app.installation_id', true), '')::uuid
$$;

CREATE FUNCTION authz.original_actor_id() RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT NULLIF(current_setting('app.original_actor_id', true), '')::uuid
$$;

CREATE FUNCTION authz.link_ids() RETURNS UUID[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT string_to_array(NULLIF(current_setting('app.link_ids', true), ''), ',')::uuid[]
$$;

CREATE FUNCTION authz.verified_email() RETURNS TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT lower(NULLIF(current_setting('app.verified_email', true), ''))
$$;

CREATE FUNCTION authz.max_tree_depth() RETURNS INTEGER
LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT 20
$$;

CREATE FUNCTION authz.caller_grantees() RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  WITH RECURSIVE reached (id) AS (
    SELECT grantee.id FROM public.grantees grantee
    WHERE grantee.id = authz.caller_id() AND grantee.kind IN ('user', 'installation')
    UNION
    SELECT grantee.id FROM public.grantees grantee WHERE grantee.kind = 'everyone'
    UNION
    SELECT grantee.id FROM public.grantees grantee
    WHERE grantee.kind = 'signed_in' AND authz.caller_id() IS NOT NULL
    UNION
    SELECT membership.organization_id FROM public.memberships membership
    WHERE membership.user_id = authz.caller_id() AND membership.state = 'active'
    UNION
    SELECT member.team_id FROM public.team_members member
    JOIN public.memberships membership ON membership.organization_id = member.organization_id AND membership.user_id = member.user_id
    WHERE member.user_id = authz.caller_id() AND membership.state = 'active'
    UNION
    SELECT link.id FROM public.share_links link
    WHERE link.id = ANY (authz.link_ids())
      AND link.revoked_at IS NULL AND (link.expires_at IS NULL OR link.expires_at > now())
    UNION
    SELECT parent.parent_id FROM public.team_parents parent JOIN reached ON parent.id = reached.id
  )
  SELECT id FROM reached
$$;

CREATE FUNCTION authz.capped_kinds(min_role authz.role)
RETURNS TABLE (organization_id UUID, kind authz.resource_kind)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT permission.organization_id, permission.kind FROM public.installation_permissions permission
  WHERE permission.installation_id = authz.acting_installation_id()
    AND permission.max_role >= min_role
$$;

CREATE FUNCTION authz.resources_with(min_role authz.role) RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  WITH RECURSIVE reached (id) AS (
    SELECT permission.resource_id FROM public.grants permission
    WHERE permission.grantee_id IN (SELECT authz.caller_grantees())
      AND permission.role >= min_role AND (permission.expires_at IS NULL OR permission.expires_at > now())
      AND NOT EXISTS (
        SELECT 1 FROM public.memberships membership
        WHERE membership.organization_id = permission.organization_id
          AND membership.user_id = permission.grantee_id AND membership.state = 'deactivated'
      )
    UNION
    SELECT child.id FROM reached CROSS JOIN LATERAL (
      SELECT parent.id FROM public.resource_parents parent WHERE parent.parent_id = reached.id
      UNION ALL
      SELECT ownable.id FROM public.ownables ownable WHERE ownable.project_id = reached.id
    ) child
  )
  SELECT resource.id FROM public.resources resource
  WHERE resource.id IN (SELECT id FROM reached)
    AND (authz.acting_installation_id() IS NULL
      OR (resource.organization_id, resource.kind) IN (SELECT * FROM authz.capped_kinds(min_role)))
$$;

CREATE FUNCTION authz.sharable_grants() RETURNS TABLE (resource_id UUID, role authz.role)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT resource.id, allowed.role
  FROM authz.resources_with('admin') resource(id)
  CROSS JOIN unnest(enum_range(NULL::authz.role)) allowed(role)
  UNION
  SELECT resource.id, allowed.role FROM public.resources resource
  CROSS JOIN (VALUES ('reader'::authz.role), ('writer'::authz.role)) allowed(role)
  WHERE resource.writers_can_share AND resource.id IN (SELECT authz.resources_with('writer'))
$$;

CREATE FUNCTION authz.member_organizations() RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT membership.organization_id FROM public.memberships membership
  WHERE membership.user_id = authz.caller_id() AND membership.state = 'active'
    AND (authz.acting_installation_id() IS NULL
      OR (membership.organization_id, 'organization'::authz.resource_kind)
        IN (SELECT * FROM authz.capped_kinds('reader')))
$$;

CREATE FUNCTION authz.co_member_users() RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT membership.user_id FROM public.memberships membership
  WHERE membership.organization_id IN (SELECT authz.member_organizations()) AND membership.state = 'active'
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

CREATE FUNCTION authz.team_admin_organizations() RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT team.organization_id FROM public.teams team WHERE team.id IN (SELECT authz.administered_teams())
$$;

CREATE FUNCTION authz.organizations_reaching(min_role authz.role) RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT resource.organization_id FROM public.resources resource WHERE resource.id IN (SELECT authz.resources_with(min_role))
$$;

CREATE FUNCTION authz.organizations_with(min_role authz.role) RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT resource.organization_id FROM public.resources resource
  WHERE resource.kind = 'organization' AND resource.id IN (SELECT authz.resources_with(min_role))
$$;

CREATE FUNCTION authz.founded_organizations() RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT organization.id FROM public.organizations organization
  WHERE organization.created_by_id = authz.caller_id() AND organization.founded_at IS NULL
$$;

CREATE FUNCTION authz.pending_invitations() RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT invitation.id FROM public.invitations invitation
  WHERE invitation.email = authz.verified_email() AND invitation.accepted_by_id IS NULL AND invitation.expires_at > now()
$$;

CREATE FUNCTION authz.is_archived(resource UUID) RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  WITH RECURSIVE ancestors (id) AS (
    SELECT resource
    UNION
    SELECT parent.id
    FROM ancestors CROSS JOIN LATERAL (
      SELECT edge.parent_id AS id FROM public.resource_parents edge WHERE edge.id = ancestors.id
      UNION ALL
      SELECT ownable.project_id FROM public.ownables ownable WHERE ownable.id = ancestors.id
    ) parent
  )
  SELECT EXISTS (
    SELECT 1 FROM ancestors
    JOIN public.resources ancestor ON ancestor.id = ancestors.id
    WHERE ancestor.archived_at IS NOT NULL
  )
$$;

CREATE FUNCTION authz.has_archived_ancestor(resource UUID) RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT EXISTS (SELECT 1 FROM public.resource_parents edge WHERE edge.id = resource AND authz.is_archived(edge.parent_id))
    OR EXISTS (SELECT 1 FROM public.ownables ownable WHERE ownable.id = resource AND authz.is_archived(ownable.project_id))
$$;

CREATE FUNCTION authz.blocking_organizations() RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT block.organization_id FROM public.organization_blocks block
  WHERE block.principal_id IN (authz.caller_id(), authz.acting_installation_id())
    AND (block.expires_at IS NULL OR block.expires_at > now())
$$;

-- An installation never acts with its user's platform authority.
CREATE FUNCTION authz.is_platform_operator() RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT authz.acting_installation_id() IS NULL
    AND EXISTS (SELECT 1 FROM public.platform_operators operator WHERE operator.id = authz.caller_id())
$$;

ALTER FUNCTION authz.caller_id() OWNER TO authz_owner;
ALTER FUNCTION authz.acting_installation_id() OWNER TO authz_owner;
ALTER FUNCTION authz.original_actor_id() OWNER TO authz_owner;
ALTER FUNCTION authz.link_ids() OWNER TO authz_owner;
ALTER FUNCTION authz.verified_email() OWNER TO authz_owner;
ALTER FUNCTION authz.max_tree_depth() OWNER TO authz_owner;
ALTER FUNCTION authz.caller_grantees() OWNER TO authz_owner;
ALTER FUNCTION authz.capped_kinds(authz.role) OWNER TO authz_owner;
ALTER FUNCTION authz.resources_with(authz.role) OWNER TO authz_owner;
ALTER FUNCTION authz.sharable_grants() OWNER TO authz_owner;
ALTER FUNCTION authz.member_organizations() OWNER TO authz_owner;
ALTER FUNCTION authz.co_member_users() OWNER TO authz_owner;
ALTER FUNCTION authz.administered_teams() OWNER TO authz_owner;
ALTER FUNCTION authz.team_admin_organizations() OWNER TO authz_owner;
ALTER FUNCTION authz.organizations_reaching(authz.role) OWNER TO authz_owner;
ALTER FUNCTION authz.organizations_with(authz.role) OWNER TO authz_owner;
ALTER FUNCTION authz.founded_organizations() OWNER TO authz_owner;
ALTER FUNCTION authz.pending_invitations() OWNER TO authz_owner;
ALTER FUNCTION authz.is_archived(UUID) OWNER TO authz_owner;
ALTER FUNCTION authz.has_archived_ancestor(UUID) OWNER TO authz_owner;
ALTER FUNCTION authz.blocking_organizations() OWNER TO authz_owner;
ALTER FUNCTION authz.is_platform_operator() OWNER TO authz_owner;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC, app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO app;

REVOKE ALL ON grantees, users, platform_operators, organizations, memberships, invitations, teams, team_parents, team_members, resources, resource_parents, ownables, grants, share_links, organization_blocks, apps, app_installations, installation_permissions, audit_events, platform_audit_events FROM PUBLIC, app, identity_writer;

GRANT SELECT ON users TO app;
GRANT SELECT, INSERT ON users TO identity_writer;
CREATE POLICY users_select ON users FOR SELECT TO app
  USING (id = (SELECT authz.caller_id())
    OR id = ANY (ARRAY(SELECT authz.co_member_users())));
CREATE POLICY users_identity_select ON users FOR SELECT TO identity_writer
  USING (TRUE);
CREATE POLICY users_insert ON users FOR INSERT TO identity_writer
  WITH CHECK (TRUE);

GRANT SELECT, DELETE ON organizations TO app;
GRANT INSERT (id, created_by_id) ON organizations TO app;
CREATE POLICY organizations_select ON organizations FOR SELECT TO app
  USING (id = ANY (ARRAY(SELECT authz.organizations_with('reader'))));
CREATE POLICY organizations_delete ON organizations FOR DELETE TO app
  USING (id = ANY (ARRAY(SELECT authz.organizations_with('admin'))));
CREATE POLICY organizations_insert ON organizations FOR INSERT TO app
  WITH CHECK (created_by_id = (SELECT authz.caller_id()) AND (SELECT authz.acting_installation_id()) IS NULL);

GRANT SELECT, INSERT, UPDATE (state), DELETE ON memberships TO app;
CREATE POLICY memberships_select ON memberships FOR SELECT TO app
  USING ((organization_id = ANY (ARRAY(SELECT authz.member_organizations())))
    OR (user_id = (SELECT authz.caller_id())
      AND ((SELECT authz.acting_installation_id()) IS NULL
        OR (organization_id, 'organization'::authz.resource_kind) IN (SELECT * FROM authz.capped_kinds('reader')))));
CREATE POLICY memberships_insert ON memberships FOR INSERT TO app
  WITH CHECK ((organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))) AND invitation_id IS NULL)
    OR (organization_id = ANY (ARRAY(SELECT authz.founded_organizations()))
      AND user_id = (SELECT authz.caller_id()) AND state = 'active' AND invitation_id IS NULL
      AND (SELECT authz.acting_installation_id()) IS NULL)
    OR (invitation_id = ANY (ARRAY(SELECT authz.pending_invitations()))
      AND user_id = (SELECT authz.caller_id()) AND state = 'active'
      AND ((SELECT authz.acting_installation_id()) IS NULL
        OR (organization_id, 'organization'::authz.resource_kind) IN (SELECT * FROM authz.capped_kinds('writer')))));
CREATE POLICY memberships_update ON memberships FOR UPDATE TO app
  USING (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))))
  WITH CHECK (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))));
CREATE POLICY memberships_delete ON memberships FOR DELETE TO app
  USING ((organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))))
    OR (user_id = (SELECT authz.caller_id())
      AND ((SELECT authz.acting_installation_id()) IS NULL
        OR (organization_id, 'organization'::authz.resource_kind) IN (SELECT * FROM authz.capped_kinds('writer')))));

GRANT SELECT, DELETE ON invitations TO app;
GRANT INSERT (id, organization_id, email, expires_at, invited_by_id) ON invitations TO app;
CREATE POLICY invitations_select ON invitations FOR SELECT TO app
  USING ((organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))))
    OR (email = (SELECT authz.verified_email())
      AND ((SELECT authz.acting_installation_id()) IS NULL
        OR (organization_id, 'organization'::authz.resource_kind) IN (SELECT * FROM authz.capped_kinds('reader')))));
CREATE POLICY invitations_insert ON invitations FOR INSERT TO app
  WITH CHECK (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))) AND invited_by_id = (SELECT authz.caller_id()));
CREATE POLICY invitations_delete ON invitations FOR DELETE TO app
  USING (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))));

GRANT SELECT, INSERT, DELETE ON teams TO app;
CREATE POLICY teams_select ON teams FOR SELECT TO app
  USING (organization_id = ANY (ARRAY(SELECT authz.member_organizations())));
CREATE POLICY teams_insert ON teams FOR INSERT TO app
  WITH CHECK ((organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))))
    OR (organization_id = ANY (ARRAY(SELECT authz.team_admin_organizations()))));
CREATE POLICY teams_delete ON teams FOR DELETE TO app
  USING (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))));
GRANT SELECT, INSERT, UPDATE (parent_id), DELETE ON team_parents TO app;
CREATE POLICY team_parents_select ON team_parents FOR SELECT TO app
  USING (organization_id = ANY (ARRAY(SELECT authz.member_organizations())));
CREATE POLICY team_parents_insert ON team_parents FOR INSERT TO app
  WITH CHECK ((organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))))
    OR (parent_id = ANY (ARRAY(SELECT authz.administered_teams()))));
CREATE POLICY team_parents_update ON team_parents FOR UPDATE TO app
  USING (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))))
  WITH CHECK (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))));
CREATE POLICY team_parents_delete ON team_parents FOR DELETE TO app
  USING (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))));

GRANT SELECT, INSERT, UPDATE (team_role), DELETE ON team_members TO app;
CREATE POLICY team_members_select ON team_members FOR SELECT TO app
  USING (organization_id = ANY (ARRAY(SELECT authz.member_organizations())));
CREATE POLICY team_members_insert ON team_members FOR INSERT TO app
  WITH CHECK ((organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))))
    OR (team_id = ANY (ARRAY(SELECT authz.administered_teams()))));
CREATE POLICY team_members_update ON team_members FOR UPDATE TO app
  USING ((organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))))
    OR (team_id = ANY (ARRAY(SELECT authz.administered_teams()))))
  WITH CHECK ((organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))))
    OR (team_id = ANY (ARRAY(SELECT authz.administered_teams()))));
CREATE POLICY team_members_delete ON team_members FOR DELETE TO app
  USING ((organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))))
    OR (team_id = ANY (ARRAY(SELECT authz.administered_teams()))));

GRANT SELECT, INSERT, UPDATE (archived_at, writers_can_share), DELETE ON resources TO app;
CREATE POLICY resources_select ON resources FOR SELECT TO app
  USING (id = ANY (ARRAY(SELECT authz.resources_with('reader'))));
CREATE POLICY resources_insert ON resources FOR INSERT TO app
  WITH CHECK ((kind IN ('folder', 'project')
      AND organization_id = ANY (ARRAY(SELECT authz.organizations_reaching('admin')))
      AND ((SELECT authz.acting_installation_id()) IS NULL
        OR (organization_id, kind) IN (SELECT * FROM authz.capped_kinds('admin'))))
    OR (kind = 'ownable'
      AND archived_at IS NULL
      AND organization_id = ANY (ARRAY(SELECT authz.organizations_reaching('writer')))
      AND ((SELECT authz.acting_installation_id()) IS NULL
        OR (organization_id, kind) IN (SELECT * FROM authz.capped_kinds('writer'))))
    OR (kind = 'organization' AND organization_id = ANY (ARRAY(SELECT authz.founded_organizations()))
      AND (SELECT authz.acting_installation_id()) IS NULL));
CREATE POLICY resources_update ON resources FOR UPDATE TO app
  USING (id = ANY (ARRAY(SELECT authz.resources_with('admin'))))
  WITH CHECK (id = ANY (ARRAY(SELECT authz.resources_with('admin'))));
CREATE POLICY resources_delete ON resources FOR DELETE TO app
  USING (id = ANY (ARRAY(SELECT authz.resources_with('admin'))));

GRANT SELECT, INSERT, UPDATE (parent_id, parent_kind), DELETE ON resource_parents TO app;
CREATE POLICY resource_parents_select ON resource_parents FOR SELECT TO app
  USING (id = ANY (ARRAY(SELECT authz.resources_with('reader'))));
CREATE POLICY resource_parents_insert ON resource_parents FOR INSERT TO app
  WITH CHECK (parent_id = ANY (ARRAY(SELECT authz.resources_with('admin'))));
CREATE POLICY resource_parents_update ON resource_parents FOR UPDATE TO app
  USING (parent_id = ANY (ARRAY(SELECT authz.resources_with('admin'))))
  WITH CHECK (parent_id = ANY (ARRAY(SELECT authz.resources_with('admin'))));
CREATE POLICY resource_parents_delete ON resource_parents FOR DELETE TO app
  USING (ARRAY[organization_id, parent_id] <@ ARRAY(SELECT authz.resources_with('admin')));

GRANT SELECT, INSERT, UPDATE (project_id), DELETE ON ownables TO app;
CREATE POLICY ownables_select ON ownables FOR SELECT TO app
  USING (id = ANY (ARRAY(SELECT authz.resources_with('reader'))));
CREATE POLICY ownables_insert ON ownables FOR INSERT TO app
  WITH CHECK (project_id = ANY (ARRAY(SELECT authz.resources_with('writer')))
    AND created_by_id = (SELECT authz.caller_id())
    AND ((SELECT authz.acting_installation_id()) IS NULL
      OR (organization_id, kind) IN (SELECT * FROM authz.capped_kinds('writer'))));
CREATE POLICY ownables_update ON ownables FOR UPDATE TO app
  USING (id = ANY (ARRAY(SELECT authz.resources_with('admin'))))
  WITH CHECK (project_id = ANY (ARRAY(SELECT authz.resources_with('writer'))));
CREATE POLICY ownables_delete ON ownables FOR DELETE TO app
  USING (id = ANY (ARRAY(SELECT authz.resources_with('admin'))));

GRANT SELECT, INSERT, UPDATE (role, expires_at), DELETE ON grants TO app;
CREATE POLICY grants_select ON grants FOR SELECT TO app
  USING (resource_id IN (SELECT share.resource_id FROM authz.sharable_grants() share)
    OR (grantee_id = ANY (ARRAY(SELECT authz.caller_grantees()))
      AND ((SELECT authz.acting_installation_id()) IS NULL
        OR (organization_id, 'organization'::authz.resource_kind) IN (SELECT * FROM authz.capped_kinds('reader')))));
CREATE POLICY grants_insert ON grants FOR INSERT TO app
  WITH CHECK ((resource_id, role) IN (SELECT share.resource_id, share.role FROM authz.sharable_grants() share)
    OR (resource_id = organization_id AND grantee_id = (SELECT authz.caller_id()) AND grantee_kind = 'user' AND role = 'admin'
      AND organization_id = ANY (ARRAY(SELECT authz.founded_organizations())) AND (SELECT authz.acting_installation_id()) IS NULL));
CREATE POLICY grants_update ON grants FOR UPDATE TO app
  USING ((resource_id, role) IN (SELECT share.resource_id, share.role FROM authz.sharable_grants() share))
  WITH CHECK ((resource_id, role) IN (SELECT share.resource_id, share.role FROM authz.sharable_grants() share));
CREATE POLICY grants_delete ON grants FOR DELETE TO app
  USING ((resource_id, role) IN (SELECT share.resource_id, share.role FROM authz.sharable_grants() share));

GRANT SELECT, INSERT, UPDATE (revoked_at, expires_at), DELETE ON share_links TO app;
CREATE POLICY share_links_select ON share_links FOR SELECT TO app
  USING ((organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))))
    OR (created_by_id = (SELECT authz.caller_id())
      AND ((SELECT authz.acting_installation_id()) IS NULL
        OR (organization_id, 'organization'::authz.resource_kind) IN (SELECT * FROM authz.capped_kinds('reader')))));
CREATE POLICY share_links_insert ON share_links FOR INSERT TO app
  WITH CHECK (organization_id = ANY (ARRAY(SELECT authz.member_organizations())) AND created_by_id = (SELECT authz.caller_id()));
CREATE POLICY share_links_update ON share_links FOR UPDATE TO app
  USING (revoked_at IS NULL
    AND (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin')))
      OR (created_by_id = (SELECT authz.caller_id())
        AND organization_id = ANY (ARRAY(SELECT authz.member_organizations())))))
  WITH CHECK (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin')))
    OR (created_by_id = (SELECT authz.caller_id())
      AND organization_id = ANY (ARRAY(SELECT authz.member_organizations()))));
CREATE POLICY share_links_delete ON share_links FOR DELETE TO app
  USING (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))));

GRANT SELECT, INSERT, UPDATE (expires_at), DELETE ON organization_blocks TO app;
CREATE POLICY organization_blocks_select ON organization_blocks FOR SELECT TO app
  USING (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))));
CREATE POLICY organization_blocks_insert ON organization_blocks FOR INSERT TO app
  WITH CHECK (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))));
CREATE POLICY organization_blocks_update ON organization_blocks FOR UPDATE TO app
  USING (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))))
  WITH CHECK (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))));
CREATE POLICY organization_blocks_delete ON organization_blocks FOR DELETE TO app
  USING (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))));

GRANT SELECT, INSERT, UPDATE (name), DELETE ON apps TO app;
CREATE POLICY apps_select ON apps FOR SELECT TO app
  USING (TRUE);
CREATE POLICY apps_insert ON apps FOR INSERT TO app
  WITH CHECK (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))));
CREATE POLICY apps_update ON apps FOR UPDATE TO app
  USING (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))))
  WITH CHECK (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))));
CREATE POLICY apps_delete ON apps FOR DELETE TO app
  USING (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))));
GRANT SELECT, INSERT, DELETE ON app_installations TO app;
CREATE POLICY app_installations_select ON app_installations FOR SELECT TO app
  USING (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))));
CREATE POLICY app_installations_insert ON app_installations FOR INSERT TO app
  WITH CHECK (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))));
CREATE POLICY app_installations_delete ON app_installations FOR DELETE TO app
  USING (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))));
GRANT SELECT, INSERT, DELETE ON installation_permissions TO app;
CREATE POLICY installation_permissions_select ON installation_permissions FOR SELECT TO app
  USING (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))));
CREATE POLICY installation_permissions_insert ON installation_permissions FOR INSERT TO app
  WITH CHECK (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin')))
    AND (SELECT authz.acting_installation_id()) IS NULL);
CREATE POLICY installation_permissions_delete ON installation_permissions FOR DELETE TO app
  USING (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))));

GRANT SELECT ON audit_events TO app;
CREATE POLICY audit_events_select ON audit_events FOR SELECT TO app
  USING (organization_id = ANY (ARRAY(SELECT authz.organizations_with('admin'))));

GRANT SELECT ON platform_operators TO app;
CREATE POLICY platform_operators_select ON platform_operators FOR SELECT TO app
  USING (id = (SELECT authz.caller_id()) AND (SELECT authz.acting_installation_id()) IS NULL);
GRANT SELECT ON platform_audit_events TO app;
CREATE POLICY platform_audit_events_select ON platform_audit_events FOR SELECT TO app
  USING ((SELECT authz.is_platform_operator()));

CREATE POLICY resources_archived_insert ON resources AS RESTRICTIVE FOR INSERT TO app
  WITH CHECK (NOT authz.is_archived(id) AND NOT authz.is_archived(organization_id));
CREATE POLICY resources_archived_update ON resources AS RESTRICTIVE FOR UPDATE TO app
  USING (NOT authz.has_archived_ancestor(id));
CREATE POLICY resources_archived_delete ON resources AS RESTRICTIVE FOR DELETE TO app
  USING (NOT authz.is_archived(id));
CREATE POLICY ownables_archived_insert ON ownables AS RESTRICTIVE FOR INSERT TO app
  WITH CHECK (NOT authz.is_archived(id) AND NOT authz.is_archived(project_id));
CREATE POLICY ownables_archived_update ON ownables AS RESTRICTIVE FOR UPDATE TO app
  USING (NOT authz.is_archived(id))
  WITH CHECK (NOT authz.is_archived(id) AND NOT authz.is_archived(project_id));
CREATE POLICY ownables_archived_delete ON ownables AS RESTRICTIVE FOR DELETE TO app
  USING (NOT authz.is_archived(id));
CREATE POLICY grants_archived_insert ON grants AS RESTRICTIVE FOR INSERT TO app
  WITH CHECK (NOT authz.is_archived(resource_id));
CREATE POLICY grants_archived_update ON grants AS RESTRICTIVE FOR UPDATE TO app
  USING (NOT authz.is_archived(resource_id))
  WITH CHECK (NOT authz.is_archived(resource_id));
CREATE POLICY grants_archived_delete ON grants AS RESTRICTIVE FOR DELETE TO app
  USING (NOT authz.is_archived(resource_id));
CREATE POLICY resource_parents_archived_insert ON resource_parents AS RESTRICTIVE FOR INSERT TO app
  WITH CHECK (NOT authz.is_archived(id) AND NOT authz.is_archived(parent_id));
CREATE POLICY resource_parents_archived_update ON resource_parents AS RESTRICTIVE FOR UPDATE TO app
  USING (NOT authz.is_archived(id))
  WITH CHECK (NOT authz.is_archived(id) AND NOT authz.is_archived(parent_id));
CREATE POLICY resource_parents_archived_delete ON resource_parents AS RESTRICTIVE FOR DELETE TO app
  USING (NOT authz.is_archived(id));

CREATE POLICY resources_blocked ON resources AS RESTRICTIVE FOR ALL TO app
  USING (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))))
  WITH CHECK (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))));
CREATE POLICY ownables_blocked ON ownables AS RESTRICTIVE FOR ALL TO app
  USING (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))))
  WITH CHECK (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))));
CREATE POLICY grants_blocked ON grants AS RESTRICTIVE FOR ALL TO app
  USING (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))))
  WITH CHECK (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))));
CREATE POLICY organizations_blocked ON organizations AS RESTRICTIVE FOR ALL TO app
  USING (NOT (id = ANY (ARRAY(SELECT authz.blocking_organizations()))))
  WITH CHECK (NOT (id = ANY (ARRAY(SELECT authz.blocking_organizations()))));
CREATE POLICY memberships_blocked ON memberships AS RESTRICTIVE FOR ALL TO app
  USING (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))))
  WITH CHECK (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))));
CREATE POLICY invitations_blocked ON invitations AS RESTRICTIVE FOR ALL TO app
  USING (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))))
  WITH CHECK (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))));
CREATE POLICY teams_blocked ON teams AS RESTRICTIVE FOR ALL TO app
  USING (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))))
  WITH CHECK (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))));
CREATE POLICY team_parents_blocked ON team_parents AS RESTRICTIVE FOR ALL TO app
  USING (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))))
  WITH CHECK (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))));
CREATE POLICY team_members_blocked ON team_members AS RESTRICTIVE FOR ALL TO app
  USING (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))))
  WITH CHECK (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))));
CREATE POLICY resource_parents_blocked ON resource_parents AS RESTRICTIVE FOR ALL TO app
  USING (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))))
  WITH CHECK (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))));
CREATE POLICY share_links_blocked ON share_links AS RESTRICTIVE FOR ALL TO app
  USING (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))))
  WITH CHECK (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))));
CREATE POLICY organization_blocks_blocked ON organization_blocks AS RESTRICTIVE FOR ALL TO app
  USING (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))))
  WITH CHECK (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))));
CREATE POLICY apps_blocked ON apps AS RESTRICTIVE FOR ALL TO app
  USING (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))))
  WITH CHECK (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))));
CREATE POLICY app_installations_blocked ON app_installations AS RESTRICTIVE FOR ALL TO app
  USING (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))))
  WITH CHECK (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))));
CREATE POLICY audit_events_blocked ON audit_events AS RESTRICTIVE FOR ALL TO app
  USING (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))))
  WITH CHECK (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))));
CREATE POLICY installation_permissions_blocked ON installation_permissions AS RESTRICTIVE FOR ALL TO app
  USING (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))))
  WITH CHECK (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))));

CREATE SCHEMA authz_write;
REVOKE ALL ON SCHEMA authz_write FROM PUBLIC;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE authz_writer REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
GRANT USAGE ON SCHEMA authz_write TO authz_writer;
GRANT USAGE ON SCHEMA authz TO authz_writer;
GRANT EXECUTE ON FUNCTION authz.resources_with(authz.role), authz.sharable_grants(), authz.administered_teams(),
  authz.caller_id(), authz.acting_installation_id(), authz.original_actor_id(), authz.max_tree_depth() TO authz_writer;

GRANT INSERT, DELETE ON grantees TO authz_writer;
GRANT SELECT ON grantees, users, platform_operators TO authz_writer;
GRANT UPDATE (id) ON users TO authz_writer;
GRANT SELECT ON organizations, teams, team_parents, resources, resource_parents, ownables, grants TO authz_writer;
GRANT UPDATE (id, founded_at) ON organizations TO authz_writer;
GRANT SELECT ON memberships, invitations TO authz_writer;
GRANT UPDATE (accepted_by_id) ON invitations TO authz_writer;
GRANT INSERT ON audit_events, platform_audit_events TO authz_writer;
GRANT DELETE ON grants TO authz_writer;
GRANT UPDATE (archived_at) ON resources TO authz_writer;
GRANT DELETE ON resources TO authz_writer;

CREATE FUNCTION authz_write.require_support_expiry(target_user UUID) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  -- A row version change makes stale snapshots fail serialization.
  UPDATE public.users SET id = id WHERE id = target_user;
  IF EXISTS (
    SELECT 1 FROM public.platform_operators operator
    JOIN public.grants permission ON permission.grantee_id = operator.id
    WHERE operator.id = target_user
      AND (permission.expires_at IS NULL OR NOT pg_catalog.isfinite(permission.expires_at))
  ) THEN
    RAISE EXCEPTION 'support grants require a finite expiry' USING ERRCODE = 'check_violation';
  END IF;
END
$$;

CREATE FUNCTION authz_write.check_grant_support_expiry() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  PERFORM authz_write.require_support_expiry(NEW.grantee_id);
  RETURN NEW;
END
$$;

CREATE FUNCTION authz_write.check_operator_support_expiry() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  PERFORM authz_write.require_support_expiry(NEW.id);
  RETURN NEW;
END
$$;

CREATE TRIGGER grants_support_expiry AFTER INSERT OR UPDATE ON grants
  FOR EACH ROW WHEN (NEW.grantee_kind = 'user' AND (NEW.expires_at IS NULL OR NOT isfinite(NEW.expires_at)))
  EXECUTE FUNCTION authz_write.check_grant_support_expiry();
CREATE TRIGGER platform_operators_support_expiry AFTER INSERT ON platform_operators
  FOR EACH ROW EXECUTE FUNCTION authz_write.check_operator_support_expiry();
CREATE TRIGGER platform_operators_update_support_expiry AFTER UPDATE ON platform_operators
  FOR EACH ROW WHEN (OLD.id IS DISTINCT FROM NEW.id) EXECUTE FUNCTION authz_write.check_operator_support_expiry();

CREATE FUNCTION authz_write.insert_grantee() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  INSERT INTO public.grantees (id, kind) VALUES (NEW.id, NEW.kind);
  RETURN NULL;
END
$$;

CREATE FUNCTION authz_write.delete_grantee() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  DELETE FROM public.grantees WHERE id = OLD.id;
  RETURN NULL;
END
$$;

CREATE TRIGGER users_grantee AFTER INSERT ON users FOR EACH ROW EXECUTE FUNCTION authz_write.insert_grantee();
CREATE TRIGGER users_grantee_removed AFTER DELETE ON users FOR EACH ROW EXECUTE FUNCTION authz_write.delete_grantee();
CREATE TRIGGER organizations_grantee AFTER INSERT ON organizations FOR EACH ROW EXECUTE FUNCTION authz_write.insert_grantee();
CREATE TRIGGER organizations_grantee_removed AFTER DELETE ON organizations FOR EACH ROW EXECUTE FUNCTION authz_write.delete_grantee();
CREATE TRIGGER teams_grantee AFTER INSERT ON teams FOR EACH ROW EXECUTE FUNCTION authz_write.insert_grantee();
CREATE TRIGGER teams_grantee_removed AFTER DELETE ON teams FOR EACH ROW EXECUTE FUNCTION authz_write.delete_grantee();
CREATE TRIGGER share_links_grantee AFTER INSERT ON share_links FOR EACH ROW EXECUTE FUNCTION authz_write.insert_grantee();
CREATE TRIGGER share_links_grantee_removed AFTER DELETE ON share_links FOR EACH ROW EXECUTE FUNCTION authz_write.delete_grantee();
CREATE TRIGGER app_installations_grantee AFTER INSERT ON app_installations FOR EACH ROW EXECUTE FUNCTION authz_write.insert_grantee();
CREATE TRIGGER app_installations_grantee_removed AFTER DELETE ON app_installations FOR EACH ROW EXECUTE FUNCTION authz_write.delete_grantee();

CREATE FUNCTION authz.stamp_archived_at() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = '' AS $$
BEGIN
  IF NEW.archived_at IS NOT NULL THEN
    IF TG_OP = 'UPDATE' AND OLD.archived_at IS NOT NULL THEN
      NEW.archived_at := OLD.archived_at;
    ELSE
      NEW.archived_at := now();
    END IF;
  END IF;
  RETURN NEW;
END
$$;

CREATE FUNCTION authz.stamp_revoked_at() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = '' AS $$
BEGIN
  IF NEW.revoked_at IS NOT NULL THEN
    IF TG_OP = 'UPDATE' AND OLD.revoked_at IS NOT NULL THEN
      NEW.revoked_at := OLD.revoked_at;
    ELSE
      NEW.revoked_at := now();
    END IF;
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER resources_stamp_archived_at BEFORE INSERT OR UPDATE OF archived_at ON resources
  FOR EACH ROW EXECUTE FUNCTION authz.stamp_archived_at();
CREATE TRIGGER share_links_stamp_revoked_at BEFORE INSERT OR UPDATE OF revoked_at ON share_links
  FOR EACH ROW EXECUTE FUNCTION authz.stamp_revoked_at();
REVOKE EXECUTE ON FUNCTION authz.stamp_archived_at(), authz.stamp_revoked_at() FROM PUBLIC, app;

CREATE FUNCTION authz_write.delete_ownable_resource() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  DELETE FROM public.resources WHERE id = OLD.id AND kind = 'ownable';
  RETURN NULL;
END
$$;

CREATE TRIGGER ownables_resource_removed AFTER DELETE ON ownables
  FOR EACH ROW EXECUTE FUNCTION authz_write.delete_ownable_resource();

CREATE FUNCTION authz_write.check_ownable_resource() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM public.ownables ownable WHERE ownable.id = NEW.id) THEN
    RAISE EXCEPTION 'resource % requires its ownable', NEW.id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER resources_ownable_required AFTER INSERT ON resources
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.kind = 'ownable')
  EXECUTE FUNCTION authz_write.check_ownable_resource();

CREATE FUNCTION authz_write.lock_organization(target_organization UUID) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  IF pg_catalog.current_setting('transaction_isolation') = 'repeatable read' THEN
    RAISE EXCEPTION 'organization checks require read committed or serializable' USING ERRCODE = 'invalid_transaction_state';
  END IF;
  PERFORM organization.id FROM public.organizations organization
    WHERE organization.id = target_organization FOR NO KEY UPDATE;
  RETURN FOUND;
END
$$;

CREATE FUNCTION authz_write.check_team_parent() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  ancestor_depth INTEGER;
  descendant_depth INTEGER;
  contains_cycle BOOLEAN;
BEGIN
  PERFORM authz_write.lock_organization(NEW.organization_id);
  WITH RECURSIVE ancestors (id, depth) AS (
    SELECT NEW.parent_id, 1
    UNION
    SELECT edge.parent_id, ancestors.depth + 1 FROM public.team_parents edge
    JOIN ancestors ON edge.id = ancestors.id
    WHERE ancestors.depth <= authz.max_tree_depth() AND ancestors.id <> NEW.id
  )
  SELECT max(ancestors.depth), bool_or(ancestors.id = NEW.id)
    INTO ancestor_depth, contains_cycle FROM ancestors;
  IF contains_cycle THEN
    RAISE EXCEPTION 'team % would become its own ancestor', NEW.id USING ERRCODE = 'check_violation';
  END IF;
  WITH RECURSIVE descendants (id, depth) AS (
    SELECT NEW.id, 1
    UNION
    SELECT edge.id, descendants.depth + 1 FROM public.team_parents edge
    JOIN descendants ON edge.parent_id = descendants.id
    WHERE descendants.depth <= authz.max_tree_depth()
  )
  SELECT max(descendants.depth) INTO descendant_depth FROM descendants;
  IF ancestor_depth + descendant_depth > authz.max_tree_depth() THEN
    RAISE EXCEPTION 'team % would exceed depth %', NEW.id, authz.max_tree_depth() USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE FUNCTION authz_write.check_resource_parent() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  ancestor_depth INTEGER;
  descendant_depth INTEGER;
  contains_cycle BOOLEAN;
BEGIN
  PERFORM authz_write.lock_organization(NEW.organization_id);
  WITH RECURSIVE ancestors (id, depth) AS (
    SELECT NEW.parent_id, 1
    UNION
    SELECT edge.parent_id, ancestors.depth + 1 FROM public.resource_parents edge
    JOIN ancestors ON edge.id = ancestors.id
    WHERE ancestors.depth <= authz.max_tree_depth() AND ancestors.id <> NEW.id
  )
  SELECT max(ancestors.depth) FILTER (WHERE ancestors.id <> NEW.organization_id), bool_or(ancestors.id = NEW.id)
    INTO ancestor_depth, contains_cycle FROM ancestors;
  IF contains_cycle THEN
    RAISE EXCEPTION 'resource % would become its own ancestor', NEW.id USING ERRCODE = 'check_violation';
  END IF;
  WITH RECURSIVE descendants (id, depth) AS (
    SELECT NEW.id, 1
    UNION
    SELECT edge.id, descendants.depth + 1 FROM public.resource_parents edge
    JOIN descendants ON edge.parent_id = descendants.id
    WHERE descendants.depth <= authz.max_tree_depth()
  )
  SELECT max(descendants.depth) INTO descendant_depth FROM descendants;
  IF coalesce(ancestor_depth, 0) + descendant_depth > authz.max_tree_depth() THEN
    RAISE EXCEPTION 'resource % would exceed depth %', NEW.id, authz.max_tree_depth() USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER team_parents_shape BEFORE INSERT OR UPDATE ON team_parents
  FOR EACH ROW EXECUTE FUNCTION authz_write.check_team_parent();
CREATE TRIGGER resource_parents_shape BEFORE INSERT OR UPDATE ON resource_parents
  FOR EACH ROW EXECUTE FUNCTION authz_write.check_resource_parent();

CREATE FUNCTION authz_write.check_resource_edge() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  orphan UUID;
BEGIN
  SELECT resource.id INTO orphan FROM public.resources resource
  WHERE resource.id IN (OLD.id, NEW.id) AND resource.kind IN ('folder', 'project')
    AND NOT EXISTS (SELECT 1 FROM public.resource_parents edge WHERE edge.id = resource.id);
  IF orphan IS NOT NULL THEN
    RAISE EXCEPTION 'resource % requires a parent edge', orphan USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER resources_parent_required AFTER INSERT OR UPDATE ON resources
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION authz_write.check_resource_edge();
CREATE CONSTRAINT TRIGGER resource_parents_required AFTER DELETE OR UPDATE ON resource_parents
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION authz_write.check_resource_edge();

CREATE FUNCTION authz_write.check_team_edge() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  IF NOT NEW.organization_id IN (SELECT authz.resources_with('admin')) AND NOT EXISTS (
    SELECT 1 FROM public.team_parents edge
    WHERE edge.id = NEW.id AND edge.parent_id IN (SELECT authz.administered_teams())
  ) THEN
    RAISE EXCEPTION 'team % requires an edge to a team the caller administers', NEW.id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER teams_parent_required AFTER INSERT ON teams
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION authz_write.check_team_edge();

CREATE FUNCTION authz_write.has_active_admin(target_organization UUID) RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.grants permission
    JOIN public.memberships membership
      ON membership.organization_id = permission.organization_id AND membership.user_id = permission.grantee_id
    WHERE permission.resource_id = target_organization AND permission.organization_id = target_organization
      AND permission.role = 'admin' AND permission.expires_at IS NULL AND permission.grantee_kind = 'user'
      AND membership.state = 'active'
  )
$$;

CREATE FUNCTION authz_write.require_organization_admin(target_organization UUID) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  IF NOT authz_write.lock_organization(target_organization) THEN
    RETURN;
  END IF;
  IF NOT authz_write.has_active_admin(target_organization) THEN
    RAISE EXCEPTION 'organization % would lose its last admin', target_organization USING ERRCODE = 'check_violation';
  END IF;
END
$$;

CREATE FUNCTION authz_write.check_last_admin() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  PERFORM authz_write.require_organization_admin(OLD.organization_id);
  RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER grants_last_admin AFTER UPDATE OR DELETE ON grants
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
  WHEN (OLD.role = 'admin' AND OLD.expires_at IS NULL AND OLD.grantee_kind = 'user' AND OLD.resource_id = OLD.organization_id)
  EXECUTE FUNCTION authz_write.check_last_admin();

CREATE FUNCTION authz_write.check_membership_admin() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  PERFORM authz_write.require_organization_admin(OLD.organization_id);
  RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER memberships_last_admin AFTER UPDATE OR DELETE ON memberships
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (OLD.state = 'active')
  EXECUTE FUNCTION authz_write.check_membership_admin();

CREATE FUNCTION authz_write.check_founded() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  IF NOT authz_write.has_active_admin(NEW.id) THEN
    RAISE EXCEPTION 'organization % requires an active admin', NEW.id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER organizations_admin_required AFTER INSERT ON organizations
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION authz_write.check_founded();

CREATE FUNCTION authz_write.stamp_founded_at() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  UPDATE public.organizations SET founded_at = now() WHERE id = NEW.organization_id AND founded_at IS NULL;
  RETURN NULL;
END
$$;

CREATE TRIGGER grants_founded AFTER INSERT ON grants
  FOR EACH ROW WHEN (NEW.resource_id = NEW.organization_id AND NEW.role = 'admin')
  EXECUTE FUNCTION authz_write.stamp_founded_at();

CREATE FUNCTION authz_write.delete_membership_grants() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  DELETE FROM public.grants
    WHERE organization_id = OLD.organization_id AND grantee_id = OLD.user_id AND grantee_kind = 'user';
  RETURN NULL;
END
$$;

CREATE TRIGGER memberships_grants_removed AFTER DELETE ON memberships
  FOR EACH ROW EXECUTE FUNCTION authz_write.delete_membership_grants();

CREATE FUNCTION authz_write.accept_invitation() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  UPDATE public.invitations SET accepted_by_id = NEW.user_id WHERE id = NEW.invitation_id;
  RETURN NULL;
END
$$;

CREATE TRIGGER memberships_invitation_accepted AFTER INSERT ON memberships
  FOR EACH ROW WHEN (NEW.invitation_id IS NOT NULL) EXECUTE FUNCTION authz_write.accept_invitation();

CREATE FUNCTION authz_write.record_audit_event() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  changed RECORD;
BEGIN
  IF TG_OP = 'DELETE' THEN
    changed := OLD;
  ELSE
    changed := NEW;
  END IF;
  INSERT INTO public.audit_events
    (at, organization_id, actor_id, original_actor_id, installation_id, table_name, operation, old_row, new_row)
  VALUES (
    now(), changed.organization_id, authz.caller_id(), authz.original_actor_id(),
    authz.acting_installation_id(), TG_TABLE_NAME, TG_OP::authz.audit_operation,
    CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE to_jsonb(OLD) END,
    CASE WHEN TG_OP = 'DELETE' THEN NULL ELSE to_jsonb(NEW) END
  );
  RETURN NULL;
END
$$;

CREATE FUNCTION authz_write.record_platform_audit_event() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  INSERT INTO public.platform_audit_events
    (at, actor_id, original_actor_id, installation_id, table_name, operation, old_row, new_row)
  VALUES (
    now(), authz.caller_id(), authz.original_actor_id(),
    authz.acting_installation_id(), TG_TABLE_NAME, TG_OP::authz.audit_operation,
    CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE to_jsonb(OLD) END,
    CASE WHEN TG_OP = 'DELETE' THEN NULL ELSE to_jsonb(NEW) END
  );
  RETURN NULL;
END
$$;

CREATE TRIGGER memberships_audit AFTER INSERT OR DELETE ON memberships
  FOR EACH ROW EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER memberships_update_audit AFTER UPDATE ON memberships
  FOR EACH ROW WHEN (OLD IS DISTINCT FROM NEW) EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER invitations_audit AFTER INSERT OR DELETE ON invitations
  FOR EACH ROW EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER invitations_update_audit AFTER UPDATE ON invitations
  FOR EACH ROW WHEN (OLD IS DISTINCT FROM NEW) EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER team_members_audit AFTER INSERT OR DELETE ON team_members
  FOR EACH ROW EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER team_members_update_audit AFTER UPDATE ON team_members
  FOR EACH ROW WHEN (OLD IS DISTINCT FROM NEW) EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER grants_audit AFTER INSERT OR DELETE ON grants
  FOR EACH ROW EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER grants_update_audit AFTER UPDATE ON grants
  FOR EACH ROW WHEN (OLD IS DISTINCT FROM NEW) EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER share_links_audit AFTER INSERT OR DELETE ON share_links
  FOR EACH ROW EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER share_links_update_audit AFTER UPDATE ON share_links
  FOR EACH ROW WHEN (OLD IS DISTINCT FROM NEW) EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER organization_blocks_audit AFTER INSERT OR DELETE ON organization_blocks
  FOR EACH ROW EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER organization_blocks_update_audit AFTER UPDATE ON organization_blocks
  FOR EACH ROW WHEN (OLD IS DISTINCT FROM NEW) EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER app_installations_audit AFTER INSERT OR DELETE ON app_installations
  FOR EACH ROW EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER app_installations_update_audit AFTER UPDATE ON app_installations
  FOR EACH ROW WHEN (OLD IS DISTINCT FROM NEW) EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER installation_permissions_audit AFTER INSERT OR DELETE ON installation_permissions
  FOR EACH ROW EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER installation_permissions_update_audit AFTER UPDATE ON installation_permissions
  FOR EACH ROW WHEN (OLD IS DISTINCT FROM NEW) EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER teams_audit AFTER INSERT OR DELETE ON teams
  FOR EACH ROW EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER teams_update_audit AFTER UPDATE ON teams
  FOR EACH ROW WHEN (OLD IS DISTINCT FROM NEW) EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER team_parents_audit AFTER INSERT OR DELETE ON team_parents
  FOR EACH ROW EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER team_parents_update_audit AFTER UPDATE ON team_parents
  FOR EACH ROW WHEN (OLD IS DISTINCT FROM NEW) EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER resource_parents_audit AFTER INSERT OR DELETE ON resource_parents
  FOR EACH ROW EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER resource_parents_update_audit AFTER UPDATE ON resource_parents
  FOR EACH ROW WHEN (OLD IS DISTINCT FROM NEW) EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER ownables_audit AFTER INSERT OR DELETE ON ownables
  FOR EACH ROW EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER ownables_update_audit AFTER UPDATE ON ownables
  FOR EACH ROW WHEN (OLD IS DISTINCT FROM NEW) EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER resources_audit AFTER INSERT OR DELETE ON resources
  FOR EACH ROW EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER resources_update_audit AFTER UPDATE ON resources
  FOR EACH ROW WHEN (OLD IS DISTINCT FROM NEW) EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER apps_audit AFTER INSERT OR DELETE ON apps
  FOR EACH ROW EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER apps_update_audit AFTER UPDATE ON apps
  FOR EACH ROW WHEN (OLD IS DISTINCT FROM NEW) EXECUTE FUNCTION authz_write.record_audit_event();
CREATE TRIGGER users_audit AFTER INSERT OR DELETE ON users
  FOR EACH ROW EXECUTE FUNCTION authz_write.record_platform_audit_event();
CREATE TRIGGER users_update_audit AFTER UPDATE ON users
  FOR EACH ROW WHEN (OLD IS DISTINCT FROM NEW) EXECUTE FUNCTION authz_write.record_platform_audit_event();
CREATE TRIGGER platform_operators_audit AFTER INSERT OR DELETE ON platform_operators
  FOR EACH ROW EXECUTE FUNCTION authz_write.record_platform_audit_event();
CREATE TRIGGER platform_operators_update_audit AFTER UPDATE ON platform_operators
  FOR EACH ROW WHEN (OLD IS DISTINCT FROM NEW) EXECUTE FUNCTION authz_write.record_platform_audit_event();
CREATE TRIGGER organizations_audit AFTER INSERT OR DELETE ON organizations
  FOR EACH ROW EXECUTE FUNCTION authz_write.record_platform_audit_event();
CREATE TRIGGER organizations_update_audit AFTER UPDATE ON organizations
  FOR EACH ROW WHEN (OLD IS DISTINCT FROM NEW) EXECUTE FUNCTION authz_write.record_platform_audit_event();

ALTER FUNCTION authz_write.require_support_expiry(UUID) OWNER TO authz_writer;
ALTER FUNCTION authz_write.check_grant_support_expiry() OWNER TO authz_writer;
ALTER FUNCTION authz_write.check_operator_support_expiry() OWNER TO authz_writer;
ALTER FUNCTION authz_write.insert_grantee() OWNER TO authz_writer;
ALTER FUNCTION authz_write.delete_grantee() OWNER TO authz_writer;
ALTER FUNCTION authz.stamp_archived_at() OWNER TO authz_writer;
ALTER FUNCTION authz.stamp_revoked_at() OWNER TO authz_writer;
ALTER FUNCTION authz_write.check_ownable_resource() OWNER TO authz_writer;
ALTER FUNCTION authz_write.delete_ownable_resource() OWNER TO authz_writer;
ALTER FUNCTION authz_write.lock_organization(UUID) OWNER TO authz_writer;
ALTER FUNCTION authz_write.check_team_parent() OWNER TO authz_writer;
ALTER FUNCTION authz_write.check_resource_parent() OWNER TO authz_writer;
ALTER FUNCTION authz_write.check_resource_edge() OWNER TO authz_writer;
ALTER FUNCTION authz_write.check_team_edge() OWNER TO authz_writer;
ALTER FUNCTION authz_write.has_active_admin(UUID) OWNER TO authz_writer;
ALTER FUNCTION authz_write.require_organization_admin(UUID) OWNER TO authz_writer;
ALTER FUNCTION authz_write.check_last_admin() OWNER TO authz_writer;
ALTER FUNCTION authz_write.check_membership_admin() OWNER TO authz_writer;
ALTER FUNCTION authz_write.delete_membership_grants() OWNER TO authz_writer;
ALTER FUNCTION authz_write.accept_invitation() OWNER TO authz_writer;
ALTER FUNCTION authz_write.check_founded() OWNER TO authz_writer;
ALTER FUNCTION authz_write.stamp_founded_at() OWNER TO authz_writer;
ALTER FUNCTION authz_write.record_audit_event() OWNER TO authz_writer;
ALTER FUNCTION authz_write.record_platform_audit_event() OWNER TO authz_writer;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz_write FROM PUBLIC, app;
