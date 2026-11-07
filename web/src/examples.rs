//! Curated example schemas shown as pills, one per documented RLS pattern, so a
//! visitor can load a real schema in one click.

/// Which Font Awesome glyph a pill shows. The concrete `Icon` is resolved in
/// `main.rs`, which owns the `dioxus-free-icons` dependency.
#[derive(Clone, Copy)]
pub enum ExampleIcon {
    /// Single-user ownership.
    Ownership,
    /// Group membership.
    Membership,
    /// Parent/child hierarchy.
    Parent,
    /// World-readable flag.
    PublicFlag,
    /// Role gate.
    RoleList,
    /// Combined patterns.
    Composite,
    /// Attribute condition, decided row by row.
    Attribute,
}

/// A named example schema.
pub struct Example {
    /// Short pill label.
    pub label: &'static str,
    /// One-line description used as the pill tooltip.
    pub description: &'static str,
    /// Glyph shown on the pill.
    pub icon: ExampleIcon,
    /// The SQL loaded into the editor when the pill is picked.
    pub sql: &'static str,
}

/// Direct ownership (P3): a row is visible to the user whose id matches its
/// owner column.
const OWNERSHIP: &str = "CREATE TABLE users (\n    id UUID PRIMARY KEY\n);\n\nCREATE TABLE resources (\n    id UUID PRIMARY KEY,\n    owner_id UUID REFERENCES users(id),\n    title TEXT\n);\n\nCREATE FUNCTION auth_current_user_id() RETURNS UUID\n    LANGUAGE sql STABLE\n    AS 'SELECT current_setting(''app.current_user_id'')::uuid';\n\nALTER TABLE resources ENABLE ROW LEVEL SECURITY;\n\nCREATE POLICY resources_select ON resources\n    FOR SELECT TO PUBLIC\n    USING (owner_id = auth_current_user_id());\n\nCREATE POLICY resources_delete ON resources\n    FOR DELETE TO PUBLIC\n    USING (owner_id = auth_current_user_id());\n";

/// Team membership (P4): an EXISTS subquery ties row access to membership in a
/// join table.
const MEMBERSHIP: &str = "CREATE TABLE users (\n    id UUID PRIMARY KEY\n);\n\nCREATE TABLE teams (\n    id UUID PRIMARY KEY\n);\n\nCREATE TABLE team_members (\n    team_id UUID NOT NULL REFERENCES teams(id),\n    user_id UUID NOT NULL REFERENCES users(id)\n);\n\nCREATE TABLE projects (\n    id UUID PRIMARY KEY,\n    team_id UUID NOT NULL REFERENCES teams(id),\n    name TEXT\n);\n\nCREATE FUNCTION auth_current_user_id() RETURNS UUID\n    LANGUAGE sql STABLE\n    AS 'SELECT current_setting(''app.current_user_id'')::uuid';\n\nALTER TABLE projects ENABLE ROW LEVEL SECURITY;\n\nCREATE POLICY projects_select ON projects\n    FOR SELECT TO PUBLIC\n    USING (EXISTS (\n        SELECT 1 FROM team_members\n        WHERE team_id = projects.team_id\n        AND user_id = auth_current_user_id()\n    ));\n";

/// Parent inheritance (P5): a child table inherits access from its parent via a
/// foreign key.
const PARENT: &str = "CREATE TABLE users (id UUID PRIMARY KEY);\nCREATE TABLE projects (\n  id UUID PRIMARY KEY,\n  owner_id UUID REFERENCES users(id)\n);\nCREATE TABLE tasks (\n  id UUID PRIMARY KEY,\n  project_id UUID NOT NULL REFERENCES projects(id)\n);\nALTER TABLE projects ENABLE ROW LEVEL SECURITY;\nALTER TABLE tasks ENABLE ROW LEVEL SECURITY;\nCREATE POLICY projects_owner ON projects FOR SELECT TO PUBLIC\n  USING (owner_id = current_setting('app.current_user_id'));\nCREATE POLICY tasks_inherit_project ON tasks FOR SELECT TO PUBLIC USING (\n  EXISTS (\n    SELECT 1\n    FROM projects p\n    WHERE p.id = tasks.project_id\n      AND p.owner_id = current_setting('app.current_user_id')\n  )\n);\n";

/// Public flag (P6): a boolean column makes the row world-readable.
const PUBLIC_FLAG: &str = "CREATE TABLE users (\n    id UUID PRIMARY KEY\n);\n\nCREATE TABLE articles (\n    id UUID PRIMARY KEY,\n    title TEXT,\n    is_public BOOLEAN NOT NULL DEFAULT FALSE\n);\n\nALTER TABLE articles ENABLE ROW LEVEL SECURITY;\n\nCREATE POLICY articles_select ON articles\n    FOR SELECT TO PUBLIC\n    USING (is_public = TRUE);\n";

/// Role threshold (P2): a function returns a role level checked against a list
/// of allowed values, read from the grant and team tables the app's registry names.
const ROLE_LIST: &str = "CREATE TABLE users (\n    id UUID PRIMARY KEY\n);\n\nCREATE TABLE teams (\n    id UUID PRIMARY KEY\n);\n\nCREATE TABLE team_members (\n    team_id UUID NOT NULL REFERENCES teams(id),\n    user_id UUID NOT NULL REFERENCES users(id)\n);\n\nCREATE TABLE ownables (\n    id UUID PRIMARY KEY,\n    owner_id UUID NOT NULL\n);\n\nCREATE TABLE owner_grants (\n    grantee_owner_id UUID NOT NULL,\n    granted_owner_id UUID NOT NULL,\n    role_id INTEGER NOT NULL\n);\n\nCREATE FUNCTION auth_current_user_id() RETURNS UUID\n    LANGUAGE sql STABLE\n    AS 'SELECT current_setting(''app.current_user_id'')::uuid';\n\nCREATE FUNCTION get_owner_role(user_uuid UUID, target_owner_id UUID) RETURNS INTEGER\n    LANGUAGE sql STABLE\n    AS 'SELECT 0';\n\nALTER TABLE ownables ENABLE ROW LEVEL SECURITY;\n\nCREATE POLICY ownables_read ON ownables\n    FOR SELECT TO PUBLIC\n    USING (get_owner_role(auth_current_user_id(), owner_id) IN (2, 3, 4));\n";

/// Composite OR (P8): owner access OR the public flag, combining two patterns in
/// one policy so the confidence summary and TODO panel light up.
const COMPOSITE: &str = "-- Composite of two patterns in one policy:\n--   * P3 direct ownership (owner_id matches the current user), OR\n--   * P6 public flag (is_public = TRUE makes the row world-readable).\nCREATE TABLE users (\n    id UUID PRIMARY KEY\n);\n\nCREATE TABLE documents (\n    id UUID PRIMARY KEY,\n    owner_id UUID NOT NULL REFERENCES users(id),\n    is_public BOOLEAN NOT NULL DEFAULT FALSE,\n    title TEXT\n);\n\nCREATE FUNCTION auth_current_user_id() RETURNS UUID\n    LANGUAGE sql STABLE\n    AS 'SELECT current_setting(''app.current_user_id'')::uuid';\n\nALTER TABLE documents ENABLE ROW LEVEL SECURITY;\n\nCREATE POLICY documents_select ON documents\n    FOR SELECT TO PUBLIC\n    USING (owner_id = auth_current_user_id() OR is_public = TRUE);\n";

/// Attribute condition (P9): access gated on a column value against a literal, which
/// the tuple query decides row by row, so it classifies at confidence B.
const ATTRIBUTE: &str = "-- Attribute policy (P9): access gated on a column value\n-- against a literal, which the tuple query decides row by row,\n-- classified confidence B.\nCREATE TABLE documents (\n    id UUID PRIMARY KEY,\n    status TEXT NOT NULL\n);\n\nALTER TABLE documents ENABLE ROW LEVEL SECURITY;\n\nCREATE POLICY documents_active ON documents\n    FOR SELECT TO PUBLIC\n    USING (status = 'active');\n";

/// All examples, in pill order.
pub const EXAMPLES: &[Example] = &[
    Example {
        label: "Ownership",
        description: "P3 direct ownership: a row is visible to the user whose id matches its owner column.",
        icon: ExampleIcon::Ownership,
        sql: OWNERSHIP,
    },
    Example {
        label: "Membership",
        description: "P4 EXISTS membership: access is granted through a team join table.",
        icon: ExampleIcon::Membership,
        sql: MEMBERSHIP,
    },
    Example {
        label: "Parent",
        description: "P5 parent inheritance: a child table inherits access from its parent via a foreign key.",
        icon: ExampleIcon::Parent,
        sql: PARENT,
    },
    Example {
        label: "Public flag",
        description: "P6 public boolean: a flag column makes the row world-readable.",
        icon: ExampleIcon::PublicFlag,
        sql: PUBLIC_FLAG,
    },
    Example {
        label: "Role list",
        description: "P2 role threshold: a function role level checked against a list of allowed values.",
        icon: ExampleIcon::RoleList,
        sql: ROLE_LIST,
    },
    Example {
        label: "Composite OR",
        description: "P8 composite: owner access OR public flag in one policy, exercising the confidence and TODO panels.",
        icon: ExampleIcon::Composite,
        sql: COMPOSITE,
    },
    Example {
        label: "Attribute",
        description: "P9 attribute condition: access gated on a column value (status = 'active') the tuple query decides row by row, classified confidence B.",
        icon: ExampleIcon::Attribute,
        sql: ATTRIBUTE,
    },
];
