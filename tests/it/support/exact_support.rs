//! The class of inputs the translation has to answer exactly, and cases drawn from it.
//!
//! The grammar is written from `PostgreSQL`'s own rules rather than from the recognizers. A
//! shape belongs to the class because the database decides each row from that row's values
//! and the request, so one tuple per row can carry the whole answer. Reading the class off
//! the classifier instead would make the oracle agree with the code under test by
//! construction, which is the thing this exists to avoid.
//!
//! Membership is the grammar's decision alone. A case the grammar admits has to agree with
//! `PostgreSQL` outright, and a translation reporting that it diverges on one of them is
//! reporting a defect in itself.

use core::fmt::Write as _;

use rls2fga::types::identity::MAX_OBJECT_NAME_CHARS;

/// Preconditions every admitted case satisfies, each a rule of the database.
///
/// 1. `PostgreSQL` ORs the permissive policies covering a command and ANDs the restrictive
///    ones onto that union, so however many there are the answer is a union of grants
///    narrowed by barriers. A case declares at least one permissive policy per command it
///    grants, since a command with none is denied outright.
/// 2. Every clause is an equality between one column of the guarded row and one scalar the
///    request supplies or one constant, so the row's own values settle the answer.
/// 3. The key is a single column of a type an object name can carry.
/// 4. Row-level security is on and the reader does not own the table, since an owner is
///    exempt from every policy unless the table forces it.
/// 5. Nothing the clause reads is another table, so no second table's policies apply.
/// 6. The deployment declares what the request value means. `current_setting('k')` is a
///    session key like any other, and only the deployment knows that this one carries the
///    caller's identity rather than a tenant or a flag, so an undeclared key is outside
///    the class by construction rather than by omission.
/// 7. The guarded table is not spelled as a well-known type. The translation refuses that
///    outright with `ReservedTypeName` rather than renaming anything, so it belongs outside
///    the class, and `a_table_named_as_a_reserved_type_is_refused` pins the refusal.
/// 8. Where the answer comes from a membership row, that membership table carries no row
///    security of its own. `PostgreSQL` shows every caller the same membership rows then,
///    which is what makes a tuple loaded as the owner true for everyone. A guarded
///    membership table is outside the class, and the translation says so.
pub(crate) const PRECONDITIONS: usize = 8;

/// The request-scoped values every admitted case declares, satisfying precondition 6.
pub(crate) const DECLARED_KEY: &str = r#"[{ "key": "app.who", "kind": "caller_id" }]"#;

/// The type a key column carries, which decides how an object name is spelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyType {
    /// Keys that can carry the identity encoder's own separator and escape marker.
    Text,
    Integer,
    Uuid,
}

impl KeyType {
    /// Every key type in the grammar.
    pub(crate) const ALL: [Self; 3] = [Self::Text, Self::Integer, Self::Uuid];

    fn column(self) -> &'static str {
        match self {
            Self::Text => "TEXT",
            Self::Integer => "INT",
            Self::Uuid => "UUID",
        }
    }

    /// Key values worth seeding, as SQL literals.
    ///
    /// The text keys carry `|` and `~`, which the identity encoder gives meaning to, so a
    /// case in this class also exercises the escaping.
    fn keys(self, length: KeyLength, base_type: &str, disambiguated: bool) -> Vec<String> {
        // One more key than a case has values, so the membership shape always leaves a
        // guarded row no membership row mentions.
        let short = match self {
            Self::Text => vec![
                "'plain'",
                "'pipe|key'",
                "'tilde~key'",
                "'both|and~key'",
                "'unnamed'",
            ],
            Self::Integer => vec!["1", "2", "3", "4", "5"],
            Self::Uuid => vec![
                "'00000000-0000-0000-0000-00000000000a'::uuid",
                "'00000000-0000-0000-0000-00000000000b'::uuid",
                "'00000000-0000-0000-0000-00000000000c'::uuid",
                "'00000000-0000-0000-0000-00000000000d'::uuid",
                "'00000000-0000-0000-0000-00000000000e'::uuid",
            ],
        };
        if length == KeyLength::Short || self != Self::Text {
            // Only a text key can be made long. A number and a UUID have the length their
            // type gives them, so those cases repeat the short keys deliberately rather
            // than pretending the axis reaches them.
            return short.into_iter().map(ToString::to_string).collect();
        }
        // At the boundary, not near it: one more character and the row has no name.
        let width = length.characters(base_type, disambiguated);
        (0..5)
            .map(|at| format!("'{}{at}'", "l".repeat(width - 1)))
            .collect()
    }

    fn label(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Integer => "int",
            Self::Uuid => "uuid",
        }
    }
}

/// How the policy reads the value the request supplies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Accessor {
    /// `current_setting('k')`, which raises where the caller set nothing.
    BareSetting,
    /// `current_setting('k', true)`, which yields NULL instead of raising.
    MissingOkSetting,
    /// A declared function around the bare form, so it raises as well.
    DeclaredFunction,
}

impl Accessor {
    /// Every accessor spelling in the grammar.
    pub(crate) const ALL: [Self; 3] = [
        Self::BareSetting,
        Self::MissingOkSetting,
        Self::DeclaredFunction,
    ];

    fn expression(self) -> &'static str {
        match self {
            Self::BareSetting => "current_setting('app.who')",
            Self::MissingOkSetting => "current_setting('app.who', true)",
            Self::DeclaredFunction => "auth_who()",
        }
    }

    /// Whether a caller that set nothing makes the read raise.
    ///
    /// `PostgreSQL`'s rule, not the translation's: `current_setting` without `missing_ok`
    /// raises `42704`, and wrapping it in a function does not change that.
    pub(crate) fn raises_when_unset(self) -> bool {
        matches!(self, Self::BareSetting | Self::DeclaredFunction)
    }

    fn declaration(self) -> &'static str {
        match self {
            Self::DeclaredFunction => {
                "CREATE FUNCTION auth_who() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.who'')';
"
            }
            Self::BareSetting | Self::MissingOkSetting => "",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::BareSetting => "bare",
            Self::MissingOkSetting => "missing-ok",
            Self::DeclaredFunction => "declared",
        }
    }
}

/// How the row's grants are composed.
///
/// `PostgreSQL` ORs the permissive policies on a command, so two policies and one policy
/// carrying an OR are the same database written two ways and have to answer alike. Each arm
/// is still an equality the row and the request settle, which is what keeps both inside the
/// class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Composition {
    /// One clause, one column.
    OneClause,
    /// Two permissive policies, which `PostgreSQL` composes.
    TwoPolicies,
    /// One policy whose clause carries the OR itself.
    OrClause,
}

impl Composition {
    /// Whether the row carries a second column a grant can come from.
    fn has_deputy(self) -> bool {
        !matches!(self, Self::OneClause)
    }

    fn label(self) -> &'static str {
        match self {
            Self::OneClause => "one-clause",
            Self::TwoPolicies => "two-policies",
            Self::OrClause => "or-clause",
        }
    }
}

/// How far the guarded rows sit below the table that carries the policies.
///
/// `PostgreSQL` applies the policies of the table a read names, so a read through the root
/// is filtered while a read naming a partition is filtered by nothing. The model answers
/// for the row, which is the read through the root, and the partitions are declared as
/// tables the case does not read directly. Depth is an axis because a boundary tested at
/// one level is not tested: walking one ancestor and walking to the top are the same thing
/// there, which is how the subpartition disclosure was missed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Depth {
    /// The guarded table holds its own rows.
    One,
    /// One partition below the root.
    Two,
    /// A partition of a partition.
    Three,
}

impl Depth {
    /// The partitions a case declares, root first, each a child of the one before.
    fn partitions(self) -> &'static [&'static str] {
        match self {
            Self::One => &[],
            Self::Two => &["guarded_eu"],
            Self::Three => &["guarded_eu", "guarded_eu_gold"],
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::One => "depth-one",
            Self::Two => "depth-two",
            Self::Three => "depth-three",
        }
    }
}

/// Where the answer comes from.
///
/// Either the guarded row settles it alone, or one row of a membership table does. Both are
/// decided by a single row plus the request, which is what puts them in the class, and the
/// join is where most of the review's findings lived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shape {
    /// A column of the guarded row against the request.
    SelfIdentity,
    /// A membership row naming the guarded row and the caller.
    MembershipJoin,
}

impl Shape {
    pub(crate) const ALL: [Self; 2] = [Self::SelfIdentity, Self::MembershipJoin];

    fn label(self) -> &'static str {
        match self {
            Self::SelfIdentity => "self",
            Self::MembershipJoin => "membership",
        }
    }
}

/// Whether a second table folds to the same type name as the guarded one.
///
/// `PostgreSQL` tells `"guarded"` and `"Guarded"` apart, and a type name folds case, so two
/// distinct tables arrive at one type and the translation has to keep them apart. Findings
/// 1 and 2 were both name collisions, which is why the grammar admits this rather than
/// avoiding it. A table named as a well-known type is a different matter: the translation
/// refuses that outright, so precondition 7 keeps it outside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TableName {
    /// One table, its own name.
    Plain,
    /// A second table whose name folds to the first's.
    FoldedCollision,
}

impl TableName {
    /// The names a case declares, guarded alike. The second folds onto the first.
    fn tables(self) -> Vec<&'static str> {
        match self {
            Self::Plain => vec!["\"guarded\""],
            Self::FoldedCollision => vec!["\"guarded\"", "\"Guarded\""],
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Plain => "one-table",
            Self::FoldedCollision => "folded-collision",
        }
    }
}

/// How long the key is, in characters before encoding.
///
/// An object name is capped, and the report already says a row past the cap is left out
/// while the database grants it. A key that fits is inside the class; the cap itself is a
/// boundary the runner cannot compare at all, since naming such a row raises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyLength {
    Short,
    /// Long, and still inside the cap once the type name and separator are counted.
    NearTheCap,
}

impl KeyLength {
    pub(crate) const ALL: [Self; 2] = [Self::Short, Self::NearTheCap];

    /// The longest key that still leaves every row a name.
    ///
    /// An object name is the type, a separator and the encoded key, capped whole. Derived
    /// from the cap rather than picked: a key comfortably inside it would let a budget
    /// regression reject the last thirty characters and still pass every case. One more
    /// character than this and naming the row raises, which the runner now refuses.
    ///
    /// `disambiguated` allows for the suffix a colliding type name carries, since the case
    /// cannot know the hash the translator will choose.
    fn characters(self, base_type: &str, disambiguated: bool) -> usize {
        match self {
            Self::Short => 8,
            Self::NearTheCap => {
                // `_` and eight hex digits, the shape `stable_hex_suffix` renders.
                let suffix = usize::from(disambiguated) * 9;
                MAX_OBJECT_NAME_CHARS - (base_type.chars().count() + suffix + 1)
            }
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Short => "short-key",
            Self::NearTheCap => "long-key",
        }
    }
}

/// One caller state the generated case compares.
pub(crate) struct Caller {
    /// Subject key, and the login role's name.
    #[cfg(feature = "client")]
    pub(crate) subject: &'static str,
    /// What it sets, absent where it sets nothing at all.
    pub(crate) value: Option<&'static str>,
}

/// The caller states every generated case compares.
///
/// One holding the value a row carries, one holding another, and one holding none, which is
/// the state the accessor's own spelling decides the meaning of.
pub(crate) const CALLERS: [Caller; 3] = [
    Caller {
        #[cfg(feature = "client")]
        subject: "alice",
        value: Some("alice"),
    },
    Caller {
        #[cfg(feature = "client")]
        subject: "mallory",
        value: Some("nobody"),
    },
    Caller {
        #[cfg(feature = "client")]
        subject: "silent",
        value: None,
    },
];

/// One case the grammar admits, as the SQL a runner needs.
pub(crate) struct ExactCase {
    /// Names the axes it came from, so a failure says which point of the grammar broke.
    pub(crate) name: String,
    pub(crate) schema: String,
    /// What runs before the schema, since the schema may name a role.
    #[cfg(feature = "client")]
    pub(crate) prelude: Vec<String>,
    /// Rows, and the grant the reading role needs.
    pub(crate) seed: [String; 2],
    pub(crate) accessor: Accessor,
    /// The change a write attempts, absent where the case grants reads alone.
    pub(crate) writes: Option<Write>,
    /// Tables whose rows are reached through their root rather than by name.
    pub(crate) not_read_directly: Vec<String>,
}

/// Every case the grammar admits, one per point of its axes.
///
/// Deliberately an enumeration rather than a sampler: the axes are small enough to cover
/// whole, and a failure names a point rather than a seed.
pub(crate) fn every_case() -> Vec<ExactCase> {
    let mut cases = every_shape_and_spelling();
    cases.extend(every_naming_axis());
    cases.extend(every_depth());
    cases.extend(every_composition());
    cases.extend(every_ownership());
    cases.extend(every_command());
    cases.extend(every_barrier());
    cases
}

/// Both spellings of an OR, against every accessor.
///
/// Two permissive policies and one policy carrying the OR are the same database, so the two
/// have to answer alike, and every spelling of the request has to reach both.
fn every_composition() -> Vec<ExactCase> {
    let mut cases = Vec::new();
    for composition in [Composition::TwoPolicies, Composition::OrClause] {
        for accessor in Accessor::ALL {
            cases.push(case(Point {
                accessor,
                composition,
                ..Point::base()
            }));
        }
    }
    cases
}

/// Key type against accessor spelling against nullability against shape, whole.
///
/// The shape decides which row settles the answer, and every spelling has to reach both.
fn every_shape_and_spelling() -> Vec<ExactCase> {
    let mut cases = Vec::new();
    for shape in Shape::ALL {
        for key in KeyType::ALL {
            for accessor in Accessor::ALL {
                for nullable in [false, true] {
                    cases.push(case(Point {
                        key,
                        accessor,
                        nullable,
                        shape,
                        ..Point::base()
                    }));
                }
            }
        }
    }
    cases
}

/// The two axes that only interact with naming, against the key types that reach it.
///
/// Crossing all five axes whole would be over a hundred cases against two containers for no
/// more coverage than this: a name collision is decided by the table's name and its key
/// type, and neither knows how the caller was spelled.
fn every_naming_axis() -> Vec<ExactCase> {
    let mut cases = Vec::new();
    for key in KeyType::ALL {
        for length in KeyLength::ALL {
            cases.push(case(Point {
                key,
                name: TableName::FoldedCollision,
                length,
                ..Point::base()
            }));
        }
        cases.push(case(Point {
            key,
            accessor: Accessor::BareSetting,
            nullable: true,
            length: KeyLength::NearTheCap,
            ..Point::base()
        }));
    }
    cases
}

/// Depth against every key type, since a composite key is how a partitioned table names its
/// rows and the encoder joins the parts.
fn every_depth() -> Vec<ExactCase> {
    let mut cases = Vec::new();
    for depth in [Depth::Two, Depth::Three] {
        for key in KeyType::ALL {
            cases.push(case(Point {
                key,
                depth,
                ..Point::base()
            }));
        }
    }
    cases
}

/// Each barrier shape against every accessor.
///
/// A barrier can only take rows away, so the seed carries rows the permissive clause grants
/// and the barrier removes. A translation that dropped it would hand those rows over.
fn every_barrier() -> Vec<ExactCase> {
    let mut cases = Vec::new();
    for barrier in [Barrier::OnRequest, Barrier::OnConstant] {
        for accessor in Accessor::ALL {
            cases.push(case(Point {
                accessor,
                barrier,
                ..Point::base()
            }));
        }
    }
    cases
}

fn each_accessor(vary: impl Fn(Accessor) -> Point) -> Vec<ExactCase> {
    Accessor::ALL
        .into_iter()
        .map(|accessor| case(vary(accessor)))
        .collect()
}

/// A policy per command, against every accessor.
///
/// A write is decided by the policies declared for its own command, so this is where the
/// three that no other axis reaches are compared at all.
fn every_command() -> Vec<ExactCase> {
    each_accessor(|accessor| Point {
        accessor,
        command: Command::EveryCommand,
        ..Point::base()
    })
}

/// An owner reading its own table, which only `FORCE` brings inside the class.
///
/// Against every accessor, since the owner still reads the request the same way.
fn every_ownership() -> Vec<ExactCase> {
    each_accessor(|accessor| Point {
        accessor,
        ownership: Ownership::ForcedOnReader,
        ..Point::base()
    })
}

/// Which commands the guarded table declares policies for.
///
/// Every other axis reads, so the answers come from one clause. Here each of the four
/// commands carries a policy of its own, and a write is compared as well as a read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command {
    /// `SELECT` alone, which every other axis stays at.
    ReadOnly,
    /// A policy per command, and the privileges to reach them.
    EveryCommand,
}

impl Command {
    /// Empty where the axis stays at its base, so a name carries only what moved.
    fn label(self) -> &'static str {
        match self {
            Self::ReadOnly => "",
            Self::EveryCommand => "every-command",
        }
    }
}

/// The change a write attempts, where the case grants writes at all.
///
/// The column it names is read by no policy, and neither is the key, which is all the
/// `INSERT` probe changes. That is what makes the candidate row's facts the existing row's,
/// so the question can be asked of the object that exists.
pub(crate) struct Write {
    /// `SET` clause an `UPDATE` applies.
    pub(crate) update_set: String,
}

/// What a `RESTRICTIVE` policy removes from the grant, where the case declares one.
///
/// `PostgreSQL` ANDs the restrictive policies onto the union of the permissive ones, so a
/// barrier can only take rows away. Both shapes stay row local: one compares another column
/// against the request, the other against a constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Barrier {
    /// None, which every other axis stays at.
    Absent,
    /// The request scalar again, on a column the permissive clause does not read.
    OnRequest,
    /// A constant, so the barrier answers the same for every caller.
    OnConstant,
}

impl Barrier {
    /// The policy the schema adds, and the clause it carries.
    fn ddl(self, read: &str) -> String {
        match self {
            Self::Absent => String::new(),
            Self::OnRequest => format!(
                "CREATE POLICY bar ON \"guarded\" AS RESTRICTIVE FOR SELECT\n\
                 \x20   USING (tenant = {read});\n"
            ),
            Self::OnConstant => "CREATE POLICY bar ON \"guarded\" AS RESTRICTIVE FOR SELECT\n\
                 \x20   USING (archived = false);\n"
                .to_string(),
        }
    }

    /// Empty where the axis stays at its base, so a name carries only what moved.
    fn label(self) -> &'static str {
        match self {
            Self::Absent => "",
            Self::OnRequest => "barrier-on-request",
            Self::OnConstant => "barrier-on-constant",
        }
    }
}

/// Who owns the guarded table, and whether policies reach them.
///
/// An owner is exempt from every policy on its table, so an owner reading is outside the
/// class until the table forces row-level security on itself. `FORCE` alone would change
/// nothing observable here, since the roles a case compares own nothing, so the two arrive
/// together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ownership {
    /// The role that ran the migration, whom no case reads as.
    Migration,
    /// A role the case reads as, with the table forcing its policies on it.
    ForcedOnReader,
}

impl Ownership {
    /// What the schema says after the policies.
    fn ddl(self) -> &'static str {
        match self {
            Self::Migration => "",
            Self::ForcedOnReader => {
                "ALTER TABLE \"guarded\" OWNER TO alice;\n\
                 ALTER TABLE \"guarded\" FORCE ROW LEVEL SECURITY;\n"
            }
        }
    }

    /// Empty where the axis stays at its base, so a name carries only what moved.
    fn label(self) -> &'static str {
        match self {
            Self::Migration => "",
            Self::ForcedOnReader => "forced-owner",
        }
    }
}

/// One point of the grammar, which is what a case is.
///
/// A struct rather than nine arguments: a call site says which axis it is moving, and the
/// rest come from [`Point::base`], so adding an axis does not touch every family.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Point {
    pub(crate) key: KeyType,
    pub(crate) accessor: Accessor,
    /// Whether the column a clause reads admits NULL.
    pub(crate) nullable: bool,
    pub(crate) name: TableName,
    pub(crate) length: KeyLength,
    pub(crate) shape: Shape,
    pub(crate) depth: Depth,
    pub(crate) composition: Composition,
    pub(crate) ownership: Ownership,
    pub(crate) command: Command,
    pub(crate) barrier: Barrier,
}

impl Point {
    /// The simplest point: one table, one clause, short keys, rows of its own.
    pub(crate) fn base() -> Self {
        Self {
            key: KeyType::Text,
            accessor: Accessor::MissingOkSetting,
            nullable: false,
            name: TableName::Plain,
            length: KeyLength::Short,
            shape: Shape::SelfIdentity,
            depth: Depth::One,
            composition: Composition::OneClause,
            ownership: Ownership::Migration,
            command: Command::ReadOnly,
            barrier: Barrier::Absent,
        }
    }
}

fn case(point: Point) -> ExactCase {
    let Point {
        key,
        accessor,
        nullable,
        name,
        length,
        shape,
        depth,
        composition,
        ownership,
        command,
        barrier,
    } = point;
    let tables = name.tables();
    let keys = key.keys(length, "guarded", name == TableName::FoldedCollision);
    // The values a row can carry: the caller's own, another, the empty string, and NULL
    // where the column admits it. NULL and the empty string are where an equality stops
    // behaving like one, so they are the boundaries worth seeding.
    let mut values = vec!["'alice'", "'someone_else'", "''"];
    if nullable {
        values.push("NULL");
    }
    assert!(
        values.len() <= keys.len(),
        "one key per row, or the seed collides on the primary key"
    );

    let (mut schema, seed) = match (shape, depth, composition.has_deputy(), command, barrier) {
        (
            Shape::SelfIdentity,
            Depth::One,
            false,
            Command::ReadOnly,
            Barrier::OnRequest | Barrier::OnConstant,
        ) => (
            barred_schema_of(key, accessor, nullable, barrier),
            barred_seed_of(&keys),
        ),
        (Shape::SelfIdentity, Depth::One, false, Command::EveryCommand, _) => (
            commanded_schema_of(key, accessor, nullable),
            commanded_seed_of(&keys),
        ),
        (Shape::SelfIdentity, Depth::One, false, ..) => (
            schema_of(&tables, key, accessor, nullable),
            seed_of(&tables, &keys, &values),
        ),
        (Shape::SelfIdentity, Depth::One, true, ..) => (
            composed_schema_of(key, accessor, nullable, composition),
            composed_seed_of(&keys),
        ),
        (Shape::SelfIdentity, ..) => (
            partitioned_schema_of(key, accessor, nullable, depth),
            partitioned_seed_of(&keys, &values),
        ),
        (Shape::MembershipJoin, ..) => (
            membership_schema_of(&tables, key, accessor, nullable),
            membership_seed_of(&tables, &keys, &values),
        ),
    };
    schema.push_str(ownership.ddl());

    ExactCase {
        name: [
            "exact",
            shape.label(),
            key.label(),
            accessor.label(),
            if nullable { "nullable" } else { "not-null" },
            name.label(),
            length.label(),
            depth.label(),
            composition.label(),
            ownership.label(),
            command.label(),
            barrier.label(),
        ]
        .iter()
        .filter(|segment| !segment.is_empty())
        .fold(String::new(), |mut name, segment| {
            if !name.is_empty() {
                name.push('-');
            }
            name.push_str(segment);
            name
        }),
        schema,
        // Every caller is a role before the schema runs, since a schema may name one as the
        // guarded table's owner.
        #[cfg(feature = "client")]
        prelude: CALLERS
            .iter()
            .map(|caller| format!("CREATE ROLE {} LOGIN", caller.subject))
            .collect(),
        seed,
        writes: match command {
            Command::ReadOnly => None,
            Command::EveryCommand => Some(Write {
                update_set: "title = 'changed'".to_string(),
            }),
        },
        accessor,
        not_read_directly: depth
            .partitions()
            .iter()
            .map(|partition| (*partition).to_string())
            .collect(),
    }
}

/// The guarded table partitioned, with the policy on the root alone.
///
/// A partitioned table's key has to contain its partition key, so the rows are named by two
/// columns here, which the object encoder joins. Only the root carries a policy, since that
/// is the layout the model answers for: the partitions hold the rows and filter nothing.
fn partitioned_schema_of(key: KeyType, accessor: Accessor, nullable: bool, depth: Depth) -> String {
    let null = if nullable { "" } else { " NOT NULL" };
    let mut schema = format!(
        "CREATE TABLE \"guarded\" (id {} NOT NULL, region TEXT NOT NULL, who TEXT{null},\n\
        \x20   PRIMARY KEY (id, region)) PARTITION BY LIST (region);\n",
        key.column()
    );
    schema.push_str(&partition_ddl(depth));
    schema.push_str(accessor.declaration());
    let _ = write!(
        schema,
        "ALTER TABLE \"guarded\" ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY own_0 ON \"guarded\" FOR SELECT USING (who = {});\n",
        accessor.expression()
    );
    schema
}

/// Each partition, a child of the one before it, the last holding the rows.
fn partition_ddl(depth: Depth) -> String {
    let partitions = depth.partitions();
    let mut ddl = String::new();
    for (at, partition) in partitions.iter().enumerate() {
        let parent = if at == 0 {
            "\"guarded\""
        } else {
            partitions[at - 1]
        };
        // The ones above the last partition further, so the nearest parent of the leaf
        // carries no policies of its own.
        let further = if at + 1 == partitions.len() {
            ""
        } else {
            " PARTITION BY LIST (region)"
        };
        let _ = writeln!(
            ddl,
            "CREATE TABLE {partition} PARTITION OF {parent} FOR VALUES IN ('eu'){further};"
        );
    }
    ddl
}

/// Rows inserted through the root, which routes them to the partition that holds them.
fn partitioned_seed_of(keys: &[String], values: &[&str]) -> [String; 2] {
    let mut rows = String::new();
    for (at, value) in values.iter().enumerate() {
        let joiner = if at == 0 { "" } else { ", " };
        let _ = write!(rows, "{joiner}({}, 'eu', {value})", keys[at]);
    }
    [
        format!("INSERT INTO \"guarded\" (id, region, who) VALUES {rows}"),
        "GRANT SELECT ON \"guarded\" TO alice, mallory, silent".to_string(),
    ]
}

/// The guarded table, a membership table with no security of its own, and the join.
///
/// Precondition 8 is the `ALTER TABLE` that is absent: with row security off, every caller
/// sees the same membership rows, which is what makes a tuple loaded as the owner true for
/// everyone. Turning it on puts the case outside the class, and the translation says so.
fn membership_schema_of(
    tables: &[&str],
    key: KeyType,
    accessor: Accessor,
    nullable: bool,
) -> String {
    let null = if nullable { "" } else { " NOT NULL" };
    let mut schema = String::new();
    for table in tables {
        let _ = writeln!(
            schema,
            "CREATE TABLE {table} (id {} PRIMARY KEY);",
            key.column()
        );
    }
    for (at, table) in tables.iter().enumerate() {
        let _ = writeln!(
            schema,
            "CREATE TABLE members_{at} (doc_id {} REFERENCES {table}(id), who TEXT{null});",
            key.column()
        );
    }
    schema.push_str(accessor.declaration());
    for (at, table) in tables.iter().enumerate() {
        let _ = write!(
            schema,
            "ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY own_{at} ON {table} FOR SELECT USING (EXISTS (\n\
             \x20   SELECT 1 FROM members_{at} m\n\
             \x20   WHERE m.doc_id = {table}.id AND m.who = {}));\n",
            accessor.expression()
        );
    }
    schema
}

/// Guarded rows, and one membership row for all but the last of them.
///
/// The unnamed row is the boundary that matters most here: a guarded row no membership row
/// mentions is denied to everybody, and a model keyed on the table rather than the row
/// would grant it.
fn membership_seed_of(tables: &[&str], keys: &[String], values: &[&str]) -> [String; 2] {
    let mut seed = String::new();
    let mut grants = String::new();
    for (at, table) in tables.iter().enumerate() {
        let rows: Vec<String> = keys.iter().map(|key| format!("({key})")).collect();
        let _ = write!(
            seed,
            "INSERT INTO {table} (id) VALUES {}; ",
            rows.join(", ")
        );
        // One membership row per value, and the final key left unmentioned.
        let members: Vec<String> = values
            .iter()
            .enumerate()
            .map(|(row, value)| {
                let value = if at == 0 {
                    value
                } else {
                    &values[values.len() - 1 - row]
                };
                format!("({}, {value})", keys[row])
            })
            .collect();
        let _ = write!(
            seed,
            "INSERT INTO members_{at} (doc_id, who) VALUES {}; ",
            members.join(", ")
        );
        let joiner = if at == 0 { "" } else { ", " };
        let _ = write!(grants, "{joiner}{table}, members_{at}");
    }
    [
        seed,
        format!("GRANT SELECT ON {grants} TO alice, mallory, silent"),
    ]
}

/// The tables, the accessor they read and the policy each carries.
fn schema_of(tables: &[&str], key: KeyType, accessor: Accessor, nullable: bool) -> String {
    let null = if nullable { "" } else { " NOT NULL" };
    let mut schema = String::new();
    for table in tables {
        let _ = writeln!(
            schema,
            "CREATE TABLE {table} (id {} PRIMARY KEY, who TEXT{null});",
            key.column()
        );
    }
    schema.push_str(accessor.declaration());
    for (at, table) in tables.iter().enumerate() {
        let _ = write!(
            schema,
            "ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY own_{at} ON {table} FOR SELECT USING (who = {});\n",
            accessor.expression()
        );
    }
    schema
}

/// The rows, and the grant the reading roles need.
///
/// A second table carries the same keys with its values rotated, so one type standing for
/// both tables would hand a caller the other table's row under a name it owns.
fn seed_of(tables: &[&str], keys: &[String], values: &[&str]) -> [String; 2] {
    let row_list = |rotated: bool| {
        let mut rows = String::new();
        for (at, value) in values.iter().enumerate() {
            let joiner = if at == 0 { "" } else { ", " };
            let value = if rotated {
                values[values.len() - 1 - at]
            } else {
                value
            };
            let _ = write!(rows, "{joiner}({}, {value})", keys[at]);
        }
        rows
    };
    let mut seed = String::new();
    let mut grants = String::new();
    for (at, table) in tables.iter().enumerate() {
        let _ = write!(
            seed,
            "INSERT INTO {table} (id, who) VALUES {}; ",
            row_list(at > 0)
        );
        let joiner = if at == 0 { "" } else { ", " };
        let _ = write!(grants, "{joiner}{table}");
    }
    [
        seed,
        format!("GRANT SELECT ON {grants} TO alice, mallory, silent"),
    ]
}

/// A table whose grant may come from either of two columns, composed two ways.
fn composed_schema_of(
    key: KeyType,
    accessor: Accessor,
    nullable: bool,
    composition: Composition,
) -> String {
    let null = if nullable { "" } else { " NOT NULL" };
    let mut schema = format!(
        "CREATE TABLE \"guarded\" (id {} PRIMARY KEY, who TEXT{null}, deputy TEXT);\n",
        key.column()
    );
    schema.push_str(accessor.declaration());
    schema.push_str("ALTER TABLE \"guarded\" ENABLE ROW LEVEL SECURITY;\n");
    let read = accessor.expression();
    match composition {
        // Two permissive policies, which `PostgreSQL` ORs for the command they share.
        Composition::TwoPolicies => {
            let _ = write!(
                schema,
                "CREATE POLICY own_0 ON \"guarded\" FOR SELECT USING (who = {read});\n\
                 CREATE POLICY own_1 ON \"guarded\" FOR SELECT USING (deputy = {read});\n"
            );
        }
        // The same database with the OR written out.
        Composition::OneClause | Composition::OrClause => {
            let _ = write!(
                schema,
                "CREATE POLICY own_0 ON \"guarded\" FOR SELECT\n\
                 \x20   USING (who = {read} OR deputy = {read});\n"
            );
        }
    }
    schema
}

/// One row granted through each column, one through neither, and one carrying the
/// boundaries.
///
/// The row granted only through `deputy` is what makes the second arm load bearing: drop
/// that arm and this row's answer changes.
fn composed_seed_of(keys: &[String]) -> [String; 2] {
    // The filler is nobody's identity. `'nobody'` would be mallory's, and a row carrying a
    // caller's value grants that caller a read the model answers under its subject name
    // rather than its setting, so the two sides would disagree about the seed rather than
    // about the translation.
    let rows = [
        ("'alice'", "'someone_else'"),
        ("'someone_else'", "'alice'"),
        ("'someone_else'", "'someone_else'"),
        ("''", "NULL"),
    ];
    let mut values = String::new();
    for (at, (who, deputy)) in rows.iter().enumerate() {
        let joiner = if at == 0 { "" } else { ", " };
        let _ = write!(values, "{joiner}({}, {who}, {deputy})", keys[at]);
    }
    [
        format!("INSERT INTO \"guarded\" (id, who, deputy) VALUES {values}"),
        "GRANT SELECT ON \"guarded\" TO alice, mallory, silent".to_string(),
    ]
}

/// The guarded table with a policy for each of the four commands, each reading its own
/// column.
///
/// One predicate shared by four policies would pass whatever the commands were wired to, so
/// `UPDATE` and `DELETE` read columns of their own and a row can be readable without being
/// removable. `INSERT` reads what `SELECT` reads, since `INSERT ... RETURNING` reads the new
/// row back and a row a caller may write but not see is a different question.
///
/// `UPDATE` carries a `WITH CHECK` as well, since without one `PostgreSQL` checks the
/// candidate row against the `USING` clause and the two would not be separable. The changed
/// column is read by no policy, so what the write produces is decided by the row it started
/// from.
fn commanded_schema_of(key: KeyType, accessor: Accessor, nullable: bool) -> String {
    let null = if nullable { "" } else { " NOT NULL" };
    let mut schema = format!(
        "CREATE TABLE \"guarded\" (id {} PRIMARY KEY, who TEXT{null}, editor TEXT,\n\
        \x20   remover TEXT, title TEXT);\n",
        key.column()
    );
    schema.push_str(accessor.declaration());
    schema.push_str("ALTER TABLE \"guarded\" ENABLE ROW LEVEL SECURITY;\n");
    let read = accessor.expression();
    let _ = write!(
        schema,
        "CREATE POLICY own_sel ON \"guarded\" FOR SELECT USING (who = {read});\n\
         CREATE POLICY own_ins ON \"guarded\" FOR INSERT WITH CHECK (who = {read});\n\
         CREATE POLICY own_upd ON \"guarded\" FOR UPDATE USING (editor = {read})\n\
         \x20   WITH CHECK (editor = {read});\n\
         CREATE POLICY own_del ON \"guarded\" FOR DELETE USING (remover = {read});\n"
    );
    schema
}

/// One row per subset of the commands, and every privilege a compared statement needs.
///
/// Readable and nothing more, readable and changeable, readable and removable, and a row
/// whose columns name the caller for the writes while hiding it from the read.
fn commanded_seed_of(keys: &[String]) -> [String; 2] {
    let rows = [
        ("'alice'", "'someone_else'", "'someone_else'"),
        ("'alice'", "'alice'", "'someone_else'"),
        ("'alice'", "'someone_else'", "'alice'"),
        ("'someone_else'", "'alice'", "'alice'"),
    ];
    let mut values = String::new();
    for (at, (who, editor, remover)) in rows.iter().enumerate() {
        let joiner = if at == 0 { "" } else { ", " };
        let _ = write!(
            values,
            "{joiner}({}, {who}, {editor}, {remover}, 'kept')",
            keys[at]
        );
    }
    [
        format!("INSERT INTO \"guarded\" (id, who, editor, remover, title) VALUES {values}"),
        "GRANT SELECT, INSERT, UPDATE, DELETE ON \"guarded\" TO alice, mallory, silent".to_string(),
    ]
}

/// The guarded table with a permissive clause and a barrier narrowing it.
///
/// The barrier reads a column the permissive clause does not, so a row can be granted by one
/// and removed by the other, which is the only way a dropped barrier shows.
fn barred_schema_of(key: KeyType, accessor: Accessor, nullable: bool, barrier: Barrier) -> String {
    let null = if nullable { "" } else { " NOT NULL" };
    let mut schema = format!(
        "CREATE TABLE \"guarded\" (id {} PRIMARY KEY, who TEXT{null}, tenant TEXT,\n\
        \x20   archived BOOLEAN NOT NULL);\n",
        key.column()
    );
    schema.push_str(accessor.declaration());
    schema.push_str("ALTER TABLE \"guarded\" ENABLE ROW LEVEL SECURITY;\n");
    let read = accessor.expression();
    let _ = writeln!(
        schema,
        "CREATE POLICY own_sel ON \"guarded\" FOR SELECT USING (who = {read});"
    );
    schema.push_str(&barrier.ddl(read));
    schema
}

/// One row per side of the barrier, so both shapes have rows it removes.
///
/// Granted outright, granted by the permissive clause and removed by either barrier, denied
/// by the permissive clause alone, and granted by the request barrier while the constant one
/// removes it.
fn barred_seed_of(keys: &[String]) -> [String; 2] {
    let rows = [
        ("'alice'", "'alice'", "false"),
        ("'alice'", "'someone_else'", "true"),
        ("'someone_else'", "'alice'", "false"),
        ("'alice'", "'alice'", "true"),
    ];
    let mut values = String::new();
    for (at, (who, tenant, archived)) in rows.iter().enumerate() {
        let joiner = if at == 0 { "" } else { ", " };
        let _ = write!(
            values,
            "{joiner}({}, {who}, {tenant}, {archived})",
            keys[at]
        );
    }
    [
        format!("INSERT INTO \"guarded\" (id, who, tenant, archived) VALUES {values}"),
        "GRANT SELECT ON \"guarded\" TO alice, mallory, silent".to_string(),
    ]
}
