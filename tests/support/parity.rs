//! One runner for every `PostgreSQL` and `OpenFGA` parity case.
//!
//! A case declares data: a schema, a seed, the principals and the rows a write would
//! attempt. Which relations answer which statement, and how a row is named as an object,
//! come from the translation itself, so no case repeats that analysis.
//!
//! The comparison is the full cross product of principal, object and statement, in both
//! directions, so a case cannot check only the pairs its author thought of.

use core::time::Duration;

use std::collections::BTreeMap;
use std::fmt::Write as _;

use diesel::connection::SimpleConnection;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::sql_types::Jsonb;
use testcontainers::{ContainerAsync, GenericImage};

use rls2fga::types::{
    records_from_row, ActionAnswer, ActionRelations, ActionStatement, ConfidenceLevel,
    NoteSeverity, RequestComparison, RequestPredicate, RowNaming, RowVersion, TableId,
    TranslationNote, ValueSource,
};

use super::openfga;

/// One caller, on both sides.
///
/// Nothing in the translation says which database role a subject is, which session values
/// it sets, or which roles it holds, so a case says.
pub(crate) struct Principal {
    /// Subject key, asked about as `user:<subject>`.
    pub(crate) subject: String,
    /// Role the reading transaction switches to.
    pub(crate) login_role: String,
    /// `set_config` values the policies read, applied local to the transaction.
    pub(crate) session: Vec<(String, String)>,
    /// Request context every check carries.
    pub(crate) context: serde_json::Value,
    /// `pg_role` memberships the caller holds, which no tuple query can know.
    pub(crate) pg_roles: Vec<String>,
    /// Whether every check carries the database's clock as `request_time`.
    pub(crate) carries_request_time: bool,
    /// Whether a policy raises on a setting this caller never set.
    ///
    /// A caller holding no token is in that state and reads nothing, so the raise is a
    /// denial. Declared per caller, because everywhere else a read that raises is a case
    /// granting no privilege or naming no column.
    pub(crate) reads_an_unset_setting: bool,
}

impl Principal {
    /// A caller identified by one session setting, the ordinary shape.
    pub(crate) fn with_setting(subject: &str, login_role: &str, key: &str, value: &str) -> Self {
        Self {
            subject: subject.to_string(),
            login_role: login_role.to_string(),
            session: vec![(key.to_string(), value.to_string())],
            context: serde_json::json!({}),
            pg_roles: Vec::new(),
            carries_request_time: false,
            reads_an_unset_setting: false,
        }
    }

    /// An `app_reader` caller identified by `app.user_id`, whose `app.bot_list` holds
    /// `keys`, or who set none. The request context carries the same list.
    pub(crate) fn with_bot_list(subject: &str, keys: Option<&[&str]>) -> Self {
        let mut principal = Self::with_setting(subject, "app_reader", "app.user_id", subject)
            .with_context(serde_json::json!({ "app_bot_list": keys.unwrap_or_default() }));
        if let Some(keys) = keys {
            principal
                .session
                .push(("app.bot_list".into(), keys.join(",")));
        }
        principal
    }

    /// A caller identified by its database role alone.
    pub(crate) fn as_role(subject: &str, login_role: &str) -> Self {
        Self {
            subject: subject.to_string(),
            login_role: login_role.to_string(),
            session: Vec::new(),
            context: serde_json::json!({}),
            pg_roles: Vec::new(),
            carries_request_time: false,
            reads_an_unset_setting: false,
        }
    }

    /// The same caller, whose checks carry `context`.
    ///
    /// A condition the caller fills reads it, and only the case knows which parameter the
    /// deployment declared.
    pub(crate) fn with_context(mut self, context: serde_json::Value) -> Self {
        self.context = context;
        self
    }

    /// The same caller, whose checks carry the database's clock.
    ///
    /// A condition against the request clock needs it, and reading it from the same
    /// database the rows came from is what keeps the two sides asking about one instant.
    pub(crate) fn with_clock(mut self) -> Self {
        self.carries_request_time = true;
        self
    }

    /// The same caller, holding `roles`.
    pub(crate) fn holding(mut self, roles: &[&str]) -> Self {
        self.pg_roles = roles.iter().map(|role| (*role).to_string()).collect();
        self
    }

    /// The same caller, whose read raises because a policy reads a setting it never set.
    pub(crate) fn reading_an_unset_setting(mut self) -> Self {
        self.reads_an_unset_setting = true;
        self
    }
}

/// Whether the caller's `context` satisfies a predicate the request alone decides.
pub(crate) fn request_predicate_holds(
    predicate: &RequestPredicate,
    context: &serde_json::Value,
) -> bool {
    match predicate {
        RequestPredicate::Holds(atom) => {
            let supplied = &context[atom.request_parameter.as_str()];
            match atom.comparison {
                RequestComparison::CallerSetHolds => supplied
                    .as_array()
                    .is_some_and(|set| set.iter().any(|entry| entry == atom.value.as_str())),
                RequestComparison::CallerValueEquals => supplied == atom.value.as_str(),
            }
        }
        RequestPredicate::Any(children) => children
            .iter()
            .any(|child| request_predicate_holds(child, context)),
        RequestPredicate::All(children) => children
            .iter()
            .all(|child| request_predicate_holds(child, context)),
    }
}

/// What a write would attempt on one table.
///
/// A no-op `UPDATE` exercises `USING` and never `WITH CHECK`, so the new row is named. An
/// `INSERT` needs no declaration: the runner copies an existing row onto a fresh key.
#[derive(Default)]
pub(crate) struct Mutations {
    /// `SET` clause an `UPDATE` applies, such as `title = 'changed'`.
    pub(crate) update_set: Option<String>,
    /// Whether the change touches no column any policy reads.
    ///
    /// The tuples state facts about rows the database holds, so a judgement about the row
    /// a write would produce normally has nothing to read. Where the change cannot alter
    /// any policy's decision the resulting row's facts are the existing row's, and the
    /// question can be asked of the object that exists. Declared by the case because it is
    /// a claim about the schema, and false by default so the runner declines rather than
    /// guessing. An `INSERT` probe changes the key alone, so the claim there is that no
    /// policy reads it.
    pub(crate) check_neutral: bool,
}

/// One case, as data.
pub(crate) struct ParityCase {
    /// Store name, and the label failures carry.
    pub(crate) name: String,
    /// Statements run before the schema, for roles a policy names.
    pub(crate) prelude: Vec<String>,
    /// The schema under test.
    pub(crate) schema: String,
    /// Rows and grants applied after it.
    pub(crate) seed: Vec<String>,
    /// The callers to compare.
    pub(crate) principals: Vec<Principal>,
    /// Per table, keyed by the schema spelling, what a write would attempt.
    pub(crate) mutations: BTreeMap<String, Mutations>,
    /// Accessor metadata the deployment declares, as a fixture's
    /// `function_registry.json` holds it.
    pub(crate) registry_json: Option<String>,
    /// Request-scoped values the deployment declares, as a fixture's
    /// `session_attributes.json` holds them.
    pub(crate) attributes_json: Option<String>,
    /// Tables whose rows are not read through the table itself.
    ///
    /// A partition with row-level security off is unfiltered when it is queried directly,
    /// because `PostgreSQL` applies a parent's policies only to rows reached through the
    /// parent. The model has one answer per row whichever relation names it, so the two
    /// disagree by access path rather than by row. A case naming a partition here compares
    /// reads through the root, which is the question the model answers.
    pub(crate) not_read_directly: Vec<String>,
    /// Whether tuples come from evaluating each row rather than from the tuple SQL.
    ///
    /// A consumer watching a change stream has one row and the description, never the
    /// whole table, so the two loaders have to state the same facts. Declared by the case
    /// because a description that cannot be answered from one row is a gap, not a bug.
    pub(crate) loading_from_rows: bool,
    /// A second instant to compare at, where the case names the oracle.
    pub(crate) future: Option<FutureInstant>,
}

/// A moment the database cannot be asked about, and what it would answer there.
///
/// A guard against the clock becomes a condition rather than tuples, and at `now()` alone
/// a model that baked the clock in while loading answers correctly. Comparing at a second
/// instant is what separates the two, and `PostgreSQL` has no way to be asked what a read
/// would return later, so the case supplies the policy's own predicate at that instant.
pub(crate) struct FutureInstant {
    /// Interval past `now()`, such as `1 year`.
    pub(crate) offset: String,
    /// Rows visible at the instant, as `(subject, object)` text pairs.
    ///
    /// Bound with the instant as `$1`. The object is spelled as the model names it, so a
    /// single-column key reads `'docs:' || id`.
    pub(crate) visible: String,
}

impl ParityCase {
    /// A case with no prelude and no writes.
    pub(crate) fn reading(
        name: &str,
        schema: &str,
        seed: &[&str],
        principals: Vec<Principal>,
    ) -> Self {
        Self {
            name: name.to_string(),
            prelude: Vec::new(),
            schema: schema.to_string(),
            seed: seed.iter().map(|sql| (*sql).to_string()).collect(),
            principals,
            mutations: BTreeMap::new(),
            registry_json: None,
            attributes_json: None,
            not_read_directly: Vec::new(),
            loading_from_rows: false,
            future: None,
        }
    }

    /// The same case, loading its tuples by evaluating each row's own description.
    pub(crate) fn loading_from_rows(mut self) -> Self {
        self.loading_from_rows = true;
        self
    }

    /// The same case, also compared `offset` past `now()` against `visible`.
    pub(crate) fn also_at(mut self, offset: &str, visible: &str) -> Self {
        self.future = Some(FutureInstant {
            offset: offset.to_string(),
            visible: visible.to_string(),
        });
        self
    }

    /// The same case, with statements applied before the schema.
    pub(crate) fn after(mut self, prelude: &[&str]) -> Self {
        self.prelude = prelude.iter().map(|sql| (*sql).to_string()).collect();
        self
    }

    /// The same case, reading its schema and registry from a fixture directory.
    pub(crate) fn from_fixture(
        name: &str,
        fixture: &str,
        seed: &[&str],
        principals: Vec<Principal>,
    ) -> Self {
        let mut case = Self::reading(name, &super::read_fixture_sql(fixture), seed, principals);
        case.registry_json =
            std::fs::read_to_string(super::fixture_dir(fixture).join("function_registry.json"))
                .ok();
        case.attributes_json =
            std::fs::read_to_string(super::fixture_dir(fixture).join("session_attributes.json"))
                .ok();
        case
    }

    /// The same case, with the accessor metadata its deployment declares.
    pub(crate) fn with_registry(mut self, registry_json: &str) -> Self {
        self.registry_json = Some(registry_json.to_string());
        self
    }

    /// The same case, with the request-scoped values its deployment declares.
    pub(crate) fn with_attributes(mut self, attributes_json: &str) -> Self {
        self.attributes_json = Some(attributes_json.to_string());
        self
    }

    /// The same case, reading the named tables only through the table that types them.
    pub(crate) fn not_reading_directly(mut self, tables: &[&str]) -> Self {
        self.not_read_directly = tables.iter().map(|table| (*table).to_string()).collect();
        self
    }

    /// The same case, with what a write on `table` would attempt.
    pub(crate) fn writing(mut self, table: &str, mutations: Mutations) -> Self {
        self.mutations.insert(table.to_string(), mutations);
        self
    }
}

/// One compared pair and both answers.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Mismatch {
    /// The caller.
    pub(crate) subject: String,
    /// The object, as the model names it.
    pub(crate) object: String,
    /// The table that object is a row of, so a note naming a table can be matched to it.
    pub(crate) table: String,
    /// The statement compared.
    pub(crate) statement: ActionStatement,
    /// What the database answered.
    pub(crate) postgres: bool,
    /// What the model answered.
    pub(crate) openfga: bool,
}

impl Mismatch {
    /// Whether the two sides answered differently.
    pub(crate) fn disagrees(&self) -> bool {
        self.postgres != self.openfga
    }
}

/// Everything one case observed.
#[derive(Debug)]
pub(crate) struct Run {
    /// Every compared pair, in the order the runner walked them.
    pub(crate) observations: Vec<Mismatch>,
    /// What the translation said diverges, each with what it licenses.
    pub(crate) disclosures: Vec<Disclosure>,
}

/// Which way a divergence may go, since a gap is not symmetric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    /// The model answers less than the database. A dropped clause can only do this.
    Narrower,
    /// The model answers more. Only a note that says so licenses it.
    Wider,
}

/// Where a note says the divergence is, and which way it goes.
#[derive(Debug, Clone)]
pub(crate) enum Licence {
    /// A table, the commands affected, and the direction. The commands are empty where
    /// the note names none, which then covers every statement on that table.
    Located {
        table: String,
        commands: Vec<String>,
        direction: Direction,
    },
    /// A note that names no guarded table, so it licenses its direction anywhere in the
    /// case. `MembershipTableGuarded` names the membership table rather than the guarded
    /// one, and two more name only their policy, so none of them can be placed.
    Anywhere { direction: Direction },
}

/// One diverging note, as the property reads it.
#[derive(Debug, Clone)]
pub(crate) struct Disclosure {
    /// The sentence, for a case that requires its gap by name.
    pub(crate) text: String,
    pub(crate) licence: Licence,
}

impl Run {
    /// The pairs the two sides answered differently about.
    pub(crate) fn mismatches(&self) -> Vec<&Mismatch> {
        self.observations
            .iter()
            .filter(|observation| observation.disagrees())
            .collect()
    }

    /// What the database answered for one pair, absent where the runner did not compare it.
    pub(crate) fn postgres_answered(
        &self,
        subject: &str,
        object: &str,
        statement: ActionStatement,
    ) -> Option<bool> {
        self.observations
            .iter()
            .find(|observation| {
                observation.subject == subject
                    && observation.object == object
                    && observation.statement == statement
            })
            .map(|observation| observation.postgres)
    }

    /// How many pairs were compared, which is what stops a case passing vacuously.
    pub(crate) fn compared(&self) -> usize {
        self.observations.len()
    }
}

impl std::fmt::Display for Mismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "user:{} {:?} {}: postgres={}, openfga={}",
            self.subject, self.statement, self.object, self.postgres, self.openfga
        )
    }
}

/// The statements the runner compares, in the order a failure reports them.
///
/// `UpdateWithoutWhere` is absent and cannot be added by asking harder. A blanket update
/// reads nothing to choose rows, which is the whole point of it, so learning which rows it
/// reached means reading them, and `RETURNING` reads columns, which brings the `SELECT`
/// policies back. Measured that way every write-only row reports as unreached. Comparing it
/// needs a different measurement, such as the affected-row count against the number of
/// objects the model grants, which is an aggregate rather than a pair.
const COMPARED: [ActionStatement; 7] = [
    ActionStatement::Select,
    ActionStatement::SelectForUpdate,
    ActionStatement::Update,
    ActionStatement::Delete,
    ActionStatement::Insert,
    ActionStatement::InsertReturning,
    ActionStatement::InsertOnConflictUpdate,
];

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type = Jsonb)]
    row: serde_json::Value,
}

#[derive(QueryableByName)]
struct Instant {
    #[diesel(sql_type = diesel::sql_types::Text)]
    instant: String,
}

#[derive(QueryableByName)]
struct Counted {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    rows: i64,
}

/// One object of one table: how it is named, and the predicate that selects its row.
struct Object {
    name: String,
    table: String,
    predicate: String,
    /// The row as its owner read it, for a loader that evaluates one row and for the
    /// write probe that copies it.
    row: serde_json::Value,
    /// The columns its key is spelled from.
    keys: Vec<String>,
}

/// The key columns a table's objects are named from, or [`None`] where a column does not
/// name them.
fn key_columns(naming: &RowNaming) -> Option<Vec<&str>> {
    naming
        .key
        .parts()
        .iter()
        .map(|part| match part {
            ValueSource::Column(column) => Some(column.as_str()),
            _ => None,
        })
        .collect()
}

/// The `WHERE` clause naming one row by its key, compared as text so any key type fits.
fn key_predicate(row: &serde_json::Value, columns: &[&str]) -> String {
    let mut predicate = String::new();
    for (at, column) in columns.iter().enumerate() {
        let value = row
            .get(*column)
            .and_then(super::scalar_text)
            .unwrap_or_default();
        let joiner = if at == 0 { "" } else { " AND " };
        let _ = write!(
            predicate,
            "{joiner}\"{column}\"::text = '{}'",
            value.replace('\'', "''")
        );
    }
    predicate
}

/// Every object the model names, read as the owner so row-level security does not filter
/// the enumeration.
fn objects(conn: &mut PgConnection, naming: &[RowNaming], skipped: &[String]) -> Vec<Object> {
    let mut out = Vec::new();
    for entry in naming {
        if skipped.iter().any(|table| entry.table.name() == table) {
            continue;
        }
        let Some(columns) = key_columns(entry) else {
            continue;
        };
        let table = entry.table.sql_name();
        let rows: Vec<JsonRow> =
            diesel::sql_query(format!("SELECT to_jsonb(t) AS row FROM {table} t"))
                .load(conn)
                .unwrap_or_else(|error| panic!("reading {table} as its owner: {error}"));
        for JsonRow { row } in rows {
            // A name the renderer refuses is the row-naming divergence this suite exists to
            // find, so it fails here rather than removing the row and passing on the rest.
            // `Ok(None)` is the deliberate one: no column names that row.
            let name = match entry.render(&super::JsonRowValues(&row)) {
                Ok(Some(name)) => name,
                Ok(None) => continue,
                Err(error) => panic!("naming a row of {table}: {error}"),
            };

            let predicate = key_predicate(&row, &columns);
            out.push(Object {
                name,
                table: table.clone(),
                predicate,
                row,
                keys: columns.iter().map(|column| (*column).to_string()).collect(),
            });
        }
    }
    out
}

#[derive(QueryableByName)]
struct Granted {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    granted: bool,
}

/// Whether `role` holds `privilege` on `table`.
///
/// A table privilege is not row-level security and the model says nothing about it, so a
/// pair the caller cannot reach at all is not one to compare. Asked of `PostgreSQL` rather
/// than inferred from an error, so a missing privilege on a table a *policy* reads still
/// raises and is reported.
fn holds_privilege(conn: &mut PgConnection, role: &str, table: &str, privilege: &str) -> bool {
    let answered: Granted = diesel::sql_query("SELECT has_table_privilege($1, $2, $3) AS granted")
        .bind::<diesel::sql_types::Text, _>(role)
        .bind::<diesel::sql_types::Text, _>(table)
        .bind::<diesel::sql_types::Text, _>(privilege)
        .get_result(conn)
        .unwrap_or_else(|error| panic!("asking whether {role} may {privilege} {table}: {error}"));
    answered.granted
}

/// Switch to the caller's role and apply its session values, local to the transaction.
fn become_principal(conn: &mut PgConnection, principal: &Principal) -> QueryResult<()> {
    diesel::sql_query(format!("SET LOCAL ROLE {}", principal.login_role)).execute(conn)?;
    for (key, value) in &principal.session {
        diesel::sql_query("SELECT set_config($1, $2, true)")
            .bind::<diesel::sql_types::Text, _>(key)
            .bind::<diesel::sql_types::Text, _>(value)
            .execute(conn)?;
    }
    Ok(())
}

/// Whether the database lets `principal` reach `object` with `statement`.
///
/// Every write runs inside a savepoint and is rolled back, so one probe cannot decide the
/// next. [`None`] where the case declared no row for the write to attempt.
fn postgres_allows(
    conn: &mut PgConnection,
    case: &ParityCase,
    principal: &Principal,
    object: &Object,
    statement: ActionStatement,
    mutations: Option<&Mutations>,
    // Set where a read raised because the caller set nothing, asked once per caller.
    raised: &mut bool,
) -> Option<bool> {
    let table = &object.table;
    let predicate = &object.predicate;
    let privileges: &[&str] = match statement {
        ActionStatement::Select => &["SELECT"],
        ActionStatement::SelectForUpdate | ActionStatement::Update => &["UPDATE"],
        ActionStatement::Delete => &["DELETE"],
        ActionStatement::Insert | ActionStatement::InsertReturning => &["INSERT"],
        // An upsert may change the conflicting row, so it needs both.
        ActionStatement::InsertOnConflictUpdate => &["INSERT", "UPDATE"],
        _ => return None,
    };
    if !privileges
        .iter()
        .all(|privilege| holds_privilege(conn, &principal.login_role, table, privilege))
    {
        return None;
    }
    if matches!(
        statement,
        ActionStatement::Insert
            | ActionStatement::InsertReturning
            | ActionStatement::InsertOnConflictUpdate
    ) {
        let attempt = Attempt {
            case,
            principal,
            object,
            statement,
        };
        return postgres_allows_write_probe(conn, &attempt, raised);
    }
    let sql = match statement {
        ActionStatement::Select => {
            format!("SELECT count(*) AS rows FROM {table} WHERE {predicate}")
        }
        ActionStatement::SelectForUpdate => format!(
            "SELECT count(*) AS rows FROM (SELECT 1 FROM {table} WHERE {predicate} FOR UPDATE) s"
        ),
        ActionStatement::Update => {
            // This table's own change, or none. Reaching for the first one any table
            // declared ran another table's `SET` here, which names a column this one does
            // not have, and the error read as the policy refusing the write.
            let set = mutations?.update_set.as_deref()?;
            format!("WITH changed AS (UPDATE {table} SET {set} WHERE {predicate} RETURNING 1) SELECT count(*) AS rows FROM changed")
        }
        ActionStatement::Delete => format!(
            "WITH removed AS (DELETE FROM {table} WHERE {predicate} RETURNING 1) SELECT count(*) AS rows FROM removed"
        ),
        _ => return None,
    };

    // Always rolled back: a `DELETE` the caller may run would otherwise take the row away
    // from every caller compared after it, and the answers would depend on their order.
    let mut granted = false;
    let answered = match conn.transaction::<(), diesel::result::Error, _>(|conn| {
        become_principal(conn, principal)?;
        let counted: Counted = diesel::sql_query(&sql).get_result(conn)?;
        granted = counted.rows == 1;
        Err(diesel::result::Error::RollbackTransaction)
    }) {
        Err(diesel::result::Error::RollbackTransaction) => Ok(granted),
        Err(error) => Err(error),
        Ok(()) => unreachable!("the transaction body always rolls back"),
    };
    match answered {
        // Not asserted per read: `PostgreSQL` may settle a correlated EXISTS from the join
        // alone and never evaluate the accessor, so a row no membership row mentions is
        // denied without raising. Whether the claim still holds is asked once per caller,
        // which is a question about the caller rather than about the planner's order.
        Ok(granted) => Some(granted),
        // Row-level security raises on exactly one thing when reading: a policy that
        // expands into itself. The read returns no row, so it is a denial, and the model
        // has to deny too.
        Err(error) if reads_as_a_policy_refusal(&error) => Some(false),
        // A caller that set nothing the policy reads is denied, where the case says so.
        Err(error) if principal.reads_an_unset_setting && reads_an_unset_setting(&error) => {
            *raised = true;
            Some(false)
        }
        // Otherwise a plain read never raises, so an error is a case that granted no
        // privilege or named no column, and calling it a denial would hide the mistake.
        Err(error) if statement == ActionStatement::Select => panic!(
            "{}: reading {table} as {} raised, which row-level security never does: {error}",
            case.name, principal.login_role
        ),
        // A write the check refuses raises, and that is a denial.
        Err(_) => Some(false),
    }
}

/// Whether `error` is row-level security refusing rather than the case being wrong.
///
/// `42P17`, a policy that expands into itself. Matched on the message because diesel does
/// not surface the code, and narrowly, so a privilege error or an absent column still
/// reports rather than reading as a denial.
fn reads_as_a_policy_refusal(error: &diesel::result::Error) -> bool {
    matches!(error, diesel::result::Error::DatabaseError(_, info)
        if info.message().contains("infinite recursion detected in policy"))
}

/// Whether `error` is a policy reading a setting nobody set, `42704`.
fn reads_an_unset_setting(error: &diesel::result::Error) -> bool {
    matches!(error, diesel::result::Error::DatabaseError(_, info)
        if info.message().contains("unrecognized configuration parameter"))
}

/// The model under test, as the three things every question about it needs.
struct Model<'run> {
    client: &'run openfga::Client,
    answers: &'run [ActionRelations],
    /// For the case's name, which every refusal reports.
    case: &'run ParityCase,
}

/// Whether the model grants `principal` the statement on `object`.
async fn openfga_allows(
    model: &Model<'_>,
    principal: &Principal,
    context: &serde_json::Value,
    object: &Object,
    statement: ActionStatement,
    check_neutral: bool,
) -> Option<bool> {
    let Model {
        client,
        answers,
        case,
    } = model;
    let type_name = object
        .name
        .split_once(':')
        .map_or_else(|| object.name.as_str(), |(type_name, _)| type_name);
    // A missing answer is not a pair to leave out. Skipping it kept the non-vacuity guard
    // satisfied by the pairs that remained, so a whole table or statement could stop being
    // compared with nothing to show it had.
    let entry = answers
        .iter()
        .find(|entry| entry.type_name == *type_name && entry.statement == statement)
        .unwrap_or_else(|| {
            panic!(
                "{}: the model answers nothing for {statement:?} on '{type_name}', so the \
                 pair would go uncompared",
                case.name
            )
        });
    match &entry.answer {
        ActionAnswer::Unrestricted => Some(true),
        ActionAnswer::Denied => Some(false),
        ActionAnswer::Judged(judgements) => {
            for judgement in judgements {
                // The tuples state facts about rows the database holds, so a judgement
                // about the row a write would produce has nothing to read. Answering it
                // needs that row's records, which is not this runner's job yet.
                // An upsert probe copies every column and keeps the key, so its
                // resulting row is the existing one and no claim is needed.
                let settled = check_neutral || statement == ActionStatement::InsertOnConflictUpdate;
                if judgement.version == RowVersion::Resulting && !settled {
                    return None;
                }
                let granted = openfga::check_allowed_with_context(
                    client,
                    &format!("user:{}", principal.subject),
                    judgement.relation.as_str(),
                    &object.name,
                    context.clone(),
                )
                .await;
                if !granted {
                    return Some(false);
                }
            }
            Some(true)
        }
        // An answer the model learns to give has to be read deliberately: treating it as
        // no answer would drop the pair the way a missing entry used to.
        other => panic!(
            "{}: the model answered {other:?} for {statement:?} on '{type_name}', which this \
             runner does not read yet",
            case.name
        ),
    }
}

/// Which property a case is asserting.
///
/// The notes come from the translator under test, so they cannot be the pass condition.
/// They can say which of two properties applies, which is a question about the notes
/// themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    /// Inside the exactly supported class: the two sides must agree, note or no note.
    Exact,
    /// Outside it: the translation must say so, and the model may only be narrower.
    Disclosed,
}

/// One `PostgreSQL` and one `OpenFGA` container, shared by every case in the binary.
///
/// Starting a pair per case cost twenty-two pairs and loaded the daemon enough to fail
/// startups. Cases run one at a time against this pair instead: each gets its own database,
/// and the roles it created are dropped after it, because a role is cluster-wide and the
/// next case spells the same names.
pub(crate) struct Cluster {
    postgres: ContainerAsync<GenericImage>,
    openfga: ContainerAsync<GenericImage>,
    pg_port: u16,
    grpc_port: u16,
}

impl Cluster {
    /// Start the pair.
    pub(crate) async fn start() -> Self {
        let postgres = super::containers::start_postgres().await;
        let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
        let openfga = super::containers::start_openfga().await;
        let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
        Self {
            postgres,
            openfga,
            pg_port,
            grpc_port,
        }
    }

    fn url(&self, database: &str) -> String {
        format!(
            "postgres://{}:{}@127.0.0.1:{}/{database}",
            super::containers::PG_USER,
            super::containers::PG_PASSWORD,
            self.pg_port
        )
    }

    /// A connection to the cluster's own database, for creating and dropping others.
    fn admin(&self) -> PgConnection {
        super::containers::connect_postgres_with_retry(&self.url(super::containers::PG_DB))
    }

    /// An empty database of its own, and a connection to it.
    fn fresh_database(&self, name: &str) -> PgConnection {
        let mut admin = self.admin();
        admin
            .batch_execute(&format!("CREATE DATABASE \"{name}\""))
            .unwrap_or_else(|error| panic!("creating database {name}: {error}"));
        super::containers::connect_postgres_with_retry(&self.url(name))
    }

    /// Drop the case's database and every role it left behind.
    ///
    /// Every non-builtin role, because only this runner uses the cluster and a case's roles
    /// are named for their part in the case rather than for the case.
    fn reset(&self, name: &str) -> Result<(), diesel::result::Error> {
        let mut admin = self.admin();
        admin.batch_execute(&format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"))?;
        admin.batch_execute(
            "DO $$
                 DECLARE role_name text;
                 BEGIN
                     FOR role_name IN
                         SELECT rolname FROM pg_roles
                         WHERE rolname <> current_user AND rolname NOT LIKE 'pg\\_%'
                     LOOP
                         EXECUTE format('DROP OWNED BY %I', role_name);
                         EXECUTE format('DROP ROLE %I', role_name);
                     END LOOP;
                 END $$",
        )
    }
}

/// The database name a case runs in, unique within the binary.
fn case_database(name: &str) -> String {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let at = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let folded: String = name
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect();
    format!("case_{at}_{folded}")
}

/// Drop a case's database and roles whether or not the case reached its assertions.
///
/// A failing case that kept its database left grants on roles the next case's reset could
/// not drop, so one broken case failed every later one.
struct Cleanup<'a> {
    cluster: &'a Cluster,
    database: String,
    /// Set once the explicit path has run, so the fallback stays out of the way.
    cleaned: bool,
}

impl Cleanup<'_> {
    /// Clean up for a case that finished, where a failure is worth failing over.
    fn finish(mut self) {
        self.cleaned = true;
        self.cluster
            .reset(&self.database)
            .unwrap_or_else(|error| panic!("cleaning up after {}: {error}", self.database));
    }
}

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        if self.cleaned {
            return;
        }
        // The case is already unwinding, so a panic here would abort the process. Every
        // step can raise one: connecting to the admin database retries and then panics.
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.cluster.reset(&self.database)
        }));
        let survived = match attempt {
            Ok(Ok(())) => return,
            Ok(Err(error)) => error.to_string(),
            Err(_) => "cleaning up panicked as well".to_string(),
        };
        eprintln!("{} survived the failed case: {survived}", self.database);
    }
}

pub(crate) async fn run_with(
    cluster: &Cluster,
    case: &ParityCase,
    expectation: Class,
    doctor: impl FnOnce(Vec<ActionRelations>) -> Vec<ActionRelations>,
) -> Run {
    let database = case_database(&case.name);
    let cleanup = Cleanup {
        cluster,
        database: database.clone(),
        cleaned: false,
    };
    let mut conn = cluster.fresh_database(&database);
    let outcome = run_in(&mut conn, cluster, &database, case, expectation, doctor).await;
    drop(conn);
    cleanup.finish();
    outcome
}

/// Apply the case, translate it, load the tuples, and compare every pair.
///
/// `doctor` sees the translation's own statement answers before they are used, which is
/// how a test plants a divergence the runner has to find.
async fn run_in(
    conn: &mut PgConnection,
    cluster: &Cluster,
    database: &str,
    case: &ParityCase,
    expectation: Class,
    doctor: impl FnOnce(Vec<ActionRelations>) -> Vec<ActionRelations>,
) -> Run {
    apply_case(conn, case);
    let (planned, disclosed) = plan_case(case, expectation);

    let answers = doctor(planned.translation().action_relations().to_vec());
    let naming = planned.translation().row_naming().to_vec();

    let objects = objects(conn, &naming, &case.not_read_directly);
    let tuples = if case.loading_from_rows {
        tuples_replaying_pure_queries(conn, case, planned.tuple_queries())
    } else {
        super::execute_tuple_queries_for_parity(conn, planned.tuple_queries())
    };
    let client = provision(cluster, case, &planned.json_model(), &tuples).await;

    let clock: Instant =
        diesel::sql_query("SELECT to_char(now(), 'YYYY-MM-DD\"T\"HH24:MI:SSOF:00') AS instant")
            .get_result(&mut *conn)
            .expect("reading now() should succeed");
    let model = Model {
        client: &client,
        answers: &answers,
        case,
    };
    let mutations = resolved_mutations(case, &naming);

    let mut observations =
        compare_every_pair(cluster, database, &model, &objects, &mutations, &clock).await;
    observations
        .extend(compare_at_future_instant(conn, case, &model, &objects, &observations).await);
    Run {
        observations,
        disclosures: disclosed,
    }
}

/// Put the case's schema and rows in the database it was given.
fn apply_case(conn: &mut PgConnection, case: &ParityCase) {
    for sql in &case.prelude {
        conn.batch_execute(sql)
            .unwrap_or_else(|error| panic!("{}: prelude {sql}: {error}", case.name));
    }
    conn.batch_execute(&case.schema)
        .unwrap_or_else(|error| panic!("{}: schema: {error}", case.name));
    for sql in &case.seed {
        conn.batch_execute(sql)
            .unwrap_or_else(|error| panic!("{}: seed {sql}: {error}", case.name));
    }
}

/// Translate the case, and hold it to the class it declared.
fn plan_case(
    case: &ParityCase,
    expectation: Class,
) -> (rls2fga::translator::Outputs, Vec<Disclosure>) {
    let (classified, db, registry) = super::classify_with(
        &case.schema,
        case.registry_json.as_deref(),
        case.attributes_json.as_deref(),
    );
    let planned = super::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let disclosed: Vec<Disclosure> = planned
        .notes()
        .iter()
        .filter(|note| note.severity().diverges_from_database())
        .map(licence_of)
        .collect();
    hold_to_class(case, expectation, &disclosed);
    (planned, disclosed)
}

/// Refuse a case belonging to the other property.
///
/// Agreement is the wrong question where the translation says it diverges, and disclosure
/// is the wrong question where it says nothing.
fn hold_to_class(case: &ParityCase, expectation: Class, disclosed: &[Disclosure]) {
    match expectation {
        Class::Exact => assert!(
            disclosed.is_empty(),
            "{}: the translation already says it diverges here, so agreement is the wrong \
             question. Outside the exactly supported class the property is disclosure, not \
             equality:\n{}",
            case.name,
            sentences(disclosed)
        ),
        Class::Disclosed => assert!(
            !disclosed.is_empty(),
            "{}: nothing is disclosed, so this case is inside the exactly supported class \
             and equality is the property to assert",
            case.name
        ),
    }
}

/// Write the model and its tuples to a store of this case's own.
///
/// A model whose condition is malformed is refused outright, so the write is itself an
/// assertion about what was generated.
async fn provision(
    cluster: &Cluster,
    case: &ParityCase,
    model: &rls2fga::generator::json_model::AuthorizationModel,
    tuples: &[super::LoadedTuple],
) -> openfga::Client {
    let mut service = openfga::connect(cluster.grpc_port).await;
    let store_id = openfga::create_store(&mut service, store_name(&case.name)).await;
    let model_id = openfga::write_authorization_model(&mut service, &store_id, model).await;
    let client = service.into_client(&store_id, &model_id);

    let mut writes: Vec<_> = tuples
        .iter()
        .map(|tuple| match &tuple.condition {
            Some((condition, context)) => openfga::make_conditional_tuple(
                &tuple.object,
                &tuple.relation,
                &tuple.subject,
                condition,
                serde_json::from_str(context).expect("the row's context is JSON"),
            ),
            None => openfga::make_tuple(&tuple.object, &tuple.relation, &tuple.subject),
        })
        .collect();
    // Role membership lives outside the policy tables, so no generated query can produce it
    // and the case says which roles a caller holds.
    for principal in &case.principals {
        for role in &principal.pg_roles {
            writes.push(openfga::make_tuple(
                &format!("pg_role:{role}"),
                "usage",
                &format!("user:{}", principal.subject),
            ));
        }
    }
    openfga::write_tuples(&client, writes).await;
    client
}

/// A store name the service accepts, which caps them at 64 characters.
///
/// The tail is kept rather than the head: a generated case's name ends in the axes it came
/// from, which is what tells two of them apart.
fn store_name(case: &str) -> &str {
    let from = case.char_indices().rev().nth(63).map_or(0, |(at, _)| at);
    &case[from..]
}

/// Ask both sides about every caller, every object and every statement.
async fn compare_every_pair(
    cluster: &Cluster,
    database: &str,
    model: &Model<'_>,
    objects: &[Object],
    mutations: &BTreeMap<String, &Mutations>,
    clock: &Instant,
) -> Vec<Mismatch> {
    let case = model.case;
    let mut observations = Vec::new();
    for principal in &case.principals {
        // A connection of its own, because a caller that set nothing is a real state and a
        // shared one cannot spell it. Setting a custom key defines it for the whole session,
        // so after one caller sets `app.who` the next reads it back as the empty string
        // rather than finding it unset, and the answers would depend on the order the
        // callers were declared in.
        let mut owned = super::containers::connect_postgres_with_retry(&cluster.url(database));
        let conn = &mut owned;
        let mut raised = false;
        for object in objects {
            for statement in COMPARED {
                let candidate = mutations.get(&object.table).copied();
                let Some(postgres) = postgres_allows(
                    conn,
                    case,
                    principal,
                    object,
                    statement,
                    candidate,
                    &mut raised,
                ) else {
                    continue;
                };
                let Some(openfga) = openfga_allows(
                    model,
                    principal,
                    &asked_context(principal, clock),
                    object,
                    statement,
                    candidate.is_some_and(|mutations| mutations.check_neutral),
                )
                .await
                else {
                    continue;
                };
                observations.push(Mismatch {
                    subject: principal.subject.clone(),
                    object: object.name.clone(),
                    table: object.table.clone(),
                    statement,
                    postgres,
                    openfga,
                });
            }
        }
        assert!(
            !principal.reads_an_unset_setting || raised,
            "{}: {} claims to read a setting it never set, and no read of any row raised, \
             so the claim is stale",
            case.name,
            principal.subject
        );
    }
    observations
}

/// The context a check carries, with the database's clock where the caller needs it.
fn asked_context(principal: &Principal, clock: &Instant) -> serde_json::Value {
    let mut context = principal.context.clone();
    if principal.carries_request_time {
        if let Some(entries) = context.as_object_mut() {
            entries.insert(
                "request_time".to_string(),
                serde_json::Value::String(clock.instant.clone()),
            );
        }
    }
    context
}

/// Apply the case and compare every pair, taking the translation's answers as they are.
pub(crate) async fn run(cluster: &Cluster, case: &ParityCase) -> Run {
    run_with(cluster, case, Class::Exact, |answers| answers).await
}

/// Run [`run`] under a deadline, panicking with the case name when the deadline passes.
pub(crate) async fn run_before(cluster: &Cluster, case: &ParityCase, deadline: Duration) -> Run {
    tokio::time::timeout(deadline, run(cluster, case))
        .await
        .unwrap_or_else(|_| panic!("{} exceeded its parity deadline", case.name))
}

/// Apply a case the translation says it diverges on, and answer with what both sides said.
///
/// Refuses a case that discloses nothing, since that one belongs to [`run`].
pub(crate) async fn run_disclosing(cluster: &Cluster, case: &ParityCase) -> Run {
    run_with(cluster, case, Class::Disclosed, |answers| answers).await
}

/// Run a closed case: the database denies one object, and the disclosure notes are consistent.
///
/// Three steps the suite's invariant requires together: any one missing silently weakens the case.
pub(crate) async fn expect_denied(
    cluster: &Cluster,
    case: &ParityCase,
    subject: &str,
    object: &str,
) {
    let run = run_disclosing(cluster, case).await;
    assert_postgres(case, &run, subject, object, ActionStatement::Select, false);
    assert_disclosed_where_noted(case, &run);
}

/// Run a disclosing case, check pinned pairs, and assert no other disagreements.
///
/// Each triple is `(subject, object, visible)`, compared as `SELECT`.
pub(crate) async fn run_disclosing_and_check(
    cluster: &Cluster,
    case: &ParityCase,
    pairs: &[(&str, &str, bool)],
) {
    let run = run_disclosing(cluster, case).await;
    for &(subject, object, visible) in pairs {
        assert_postgres(
            case,
            &run,
            subject,
            object,
            ActionStatement::Select,
            visible,
        );
    }
    assert_only_disagreements(case, &run, &[]);
}

/// Refuse any disagreement outside `expected`, and refuse an expected one that agreed.
///
/// Narrower than [`assert_disclosed_where_noted`] for a disclosed case whose divergence is
/// known row by row: it also fails when the model denies something else it used to grant.
/// An empty `expected` asks for parity from a case that discloses anyway.
pub(crate) fn assert_only_disagreements(
    case: &ParityCase,
    run: &Run,
    expected: &[(&str, &str, ActionStatement)],
) {
    let named = |observation: &Mismatch| {
        expected.iter().any(|(subject, object, statement)| {
            observation.subject == *subject
                && observation.object == *object
                && observation.statement == *statement
        })
    };
    let unexpected: Vec<_> = run
        .mismatches()
        .into_iter()
        .filter(|observation| !named(observation))
        .map(ToString::to_string)
        .collect();
    assert!(
        unexpected.is_empty(),
        "{}: disagreed where the case claims parity:\n{}",
        case.name,
        unexpected.join("\n")
    );
    assert!(
        run.compared() > 0,
        "{}: nothing was compared, so parity means nothing",
        case.name
    );
    for (subject, object, statement) in expected {
        assert!(
            run.observations
                .iter()
                .any(|observation| observation.subject == *subject
                    && observation.object == *object
                    && observation.statement == *statement
                    && observation.disagrees()),
            "{}: {subject} on {statement:?} {object} agreed, so the case's claimed \
             divergence is stale",
            case.name
        );
    }
}

/// Fail with every disagreement named, and refuse a case that compared nothing.
pub(crate) fn assert_agrees(case: &ParityCase, run: &Run) {
    let mismatches = run.mismatches();
    assert!(
        mismatches.is_empty(),
        "{}: PostgreSQL and OpenFGA disagree:\n{}",
        case.name,
        mismatches
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        run.compared() > 0,
        "{}: nothing was compared, so agreeing means nothing",
        case.name
    );
}

/// Fail unless the database answered `expected` for one pair.
///
/// What a hand-written case pinned with its own `assert!(!expected)`: that the schema
/// really denies the row, so agreement is not two sides being wrong together.
pub(crate) fn assert_postgres(
    case: &ParityCase,
    run: &Run,
    subject: &str,
    object: &str,
    statement: ActionStatement,
    expected: bool,
) {
    let answered = run.postgres_answered(subject, object, statement);
    assert_eq!(
        answered,
        Some(expected),
        "{}: PostgreSQL on {subject} {statement:?} {object}",
        case.name
    );
}

/// Refuse a case whose disclosure does not name every gap the case claims.
///
/// A case reporting one gap where it has three is silent about two of them, which is the
/// defect the disclosure exists to prevent.
pub(crate) fn assert_discloses(case: &ParityCase, run: &Run, named: &[&str]) {
    for name in named {
        assert!(
            run.disclosures
                .iter()
                .any(|disclosure| disclosure.text.contains(name)),
            "{}: nothing discloses '{name}', so falling closed there is silent:\n{}",
            case.name,
            sentences(&run.disclosures)
        );
    }
}

/// One pair the case's own oracle says is visible at the future instant.
#[derive(QueryableByName)]
struct VisiblePair {
    #[diesel(sql_type = diesel::sql_types::Text)]
    subject: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    object: String,
}

/// Compare every pair again at the case's future instant, if it declared one.
///
/// A model that resolved the clock while loading tuples answers correctly at `now()` and
/// keeps granting afterwards, so the second instant is what catches it. The case supplies
/// the oracle because the database cannot be asked what a read would return later, and the
/// clock has to take something away or the comparison proves nothing.
async fn compare_at_future_instant(
    conn: &mut PgConnection,
    case: &ParityCase,
    model: &Model<'_>,
    objects: &[Object],
    at_now: &[Mismatch],
) -> Vec<Mismatch> {
    let Some(future) = case.future.as_ref() else {
        return Vec::new();
    };
    let instant: Instant = diesel::sql_query(format!(
        "SELECT to_char(now() + interval '{}', 'YYYY-MM-DD\"T\"HH24:MI:SSOF:00') AS instant",
        future.offset
    ))
    .get_result(&mut *conn)
    .unwrap_or_else(|error| panic!("{}: reading the future instant: {error}", case.name));

    let visible: Vec<VisiblePair> = diesel::sql_query(&future.visible)
        .bind::<diesel::sql_types::Text, _>(&instant.instant)
        .load(&mut *conn)
        .unwrap_or_else(|error| {
            panic!(
                "{}: the case's oracle at {} failed: {error}",
                case.name, future.offset
            )
        });

    let mut observations = Vec::new();
    for principal in &case.principals {
        for object in objects {
            let postgres = visible
                .iter()
                .any(|pair| pair.subject == principal.subject && pair.object == object.name);
            let mut context = principal.context.clone();
            if let Some(entries) = context.as_object_mut() {
                entries.insert(
                    "request_time".to_string(),
                    serde_json::Value::String(instant.instant.clone()),
                );
            }
            let Some(openfga) = openfga_allows(
                model,
                principal,
                &context,
                object,
                ActionStatement::Select,
                false,
            )
            .await
            else {
                continue;
            };
            observations.push(Mismatch {
                subject: principal.subject.clone(),
                object: object.name.clone(),
                table: object.table.clone(),
                statement: ActionStatement::Select,
                postgres,
                openfga,
            });
        }
    }
    let took_away = observations.iter().any(|later| {
        at_now.iter().any(|now| {
            now.subject == later.subject
                && now.object == later.object
                && now.statement == ActionStatement::Select
                && now.postgres
                && !later.postgres
        })
    });
    assert!(
        took_away,
        "{}: nothing loses its grant by {}, so the clock condition proves nothing",
        case.name, future.offset
    );
    observations
}

/// Load a query that one row can answer by evaluating the row, and the rest by its SQL.
///
/// A consumer watching a change stream holds one row and the description, never the whole
/// table. Replaying the pure queries this way runs none of their SQL, so a description
/// disagreeing with it about the object, the relation, the condition or the context shows
/// as a parity failure rather than as agreement between a query and itself. The impure
/// queries still load whole, since one row cannot answer them and dropping them would
/// silently narrow the case.
fn tuples_replaying_pure_queries(
    conn: &mut PgConnection,
    case: &ParityCase,
    queries: &[rls2fga::generator::tuple_generator::TupleQuery],
) -> Vec<super::LoadedTuple> {
    let mut loaded = std::collections::BTreeSet::new();
    let mut rows_by_table = BTreeMap::new();
    let mut pure = 0usize;
    for query in queries {
        if query.skipped.is_some() {
            continue;
        }
        let table = query
            .description
            .as_ref()
            .and_then(|description| description.row_table().map(TableId::sql_name));
        let (Some(description), Some(table)) = (query.description.as_ref(), table) else {
            loaded.extend(super::execute_tuple_queries_for_parity(
                conn,
                std::slice::from_ref(query),
            ));
            continue;
        };
        pure += 1;
        let rows = rows_by_table.entry(table.clone()).or_insert_with(|| {
            // The runtime source table has no typed `table!` schema.
            diesel::sql_query(format!("SELECT to_jsonb(t) AS row FROM {table} t"))
                .load::<JsonRow>(conn)
                .unwrap_or_else(|error| panic!("{}: reading {table}: {error}", case.name))
        });
        for JsonRow { row } in rows {
            let records =
                records_from_row(description, &super::JsonRowValues(row)).unwrap_or_else(|error| {
                    panic!("{}: evaluating a row of {table}: {error:?}", case.name)
                });
            for record in records {
                loaded.insert(super::LoadedTuple {
                    object: record.object,
                    relation: record.relation.as_str().to_string(),
                    subject: record.subject,
                    condition: record.context.as_ref().map(|context| {
                        let values: serde_json::Map<_, _> = context
                            .values
                            .iter()
                            .map(|(key, value)| {
                                (key.clone(), serde_json::Value::String(value.clone()))
                            })
                            .collect();
                        (
                            context.condition.to_string(),
                            serde_json::Value::Object(values).to_string(),
                        )
                    }),
                });
            }
        }
    }
    assert!(
        pure > 0,
        "{}: no description answers from one row, so this loader states nothing",
        case.name
    );
    loaded.into_iter().collect()
}

/// One question put to the database: who asks, about which row, with which statement.
#[derive(Clone, Copy)]
struct Attempt<'ask> {
    case: &'ask ParityCase,
    principal: &'ask Principal,
    object: &'ask Object,
    statement: ActionStatement,
}

/// Whether the caller may write a row copied from `object` onto a fresh key.
///
/// A write is about a row that does not exist yet, so the probe is the existing row with
/// its key replaced, which keeps every column a policy reads. The statement is always
/// rolled back, so nothing the runner compares afterwards sees the probe.
///
/// Two spellings of each statement are measured and required to agree, which is what makes
/// one relation cover both: naming a conflict arbiter reads the new row back exactly as
/// `RETURNING` does, and `ON CONFLICT` without an arbiter reads nothing back, exactly as a
/// plain `INSERT`.
fn postgres_allows_write_probe(
    conn: &mut PgConnection,
    attempt: &Attempt,
    // Set where the write raised because the caller set nothing, as a read does.
    raised: &mut bool,
) -> Option<bool> {
    let Attempt {
        case,
        object,
        statement,
        ..
    } = *attempt;
    let table = &object.table;
    let row = object.row.as_object()?;
    let keys = &object.keys;
    let arbiter = keys
        .iter()
        .map(|key| format!("\"{key}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let settable = row.keys().find(|column| !keys.contains(column))?;

    let mut probe = row.clone();
    if statement != ActionStatement::InsertOnConflictUpdate {
        for key in keys {
            let fresh = fresh_key(conn, table, key, row.get(key)?)?;
            probe.insert(key.clone(), fresh);
        }
    }
    let source = format!(
        "INSERT INTO {table} SELECT * FROM jsonb_populate_record(NULL::{table}, $1::jsonb)"
    );
    let spellings = match statement {
        ActionStatement::Insert => [source.clone(), format!("{source} ON CONFLICT DO NOTHING")],
        ActionStatement::InsertReturning => [
            format!(
                "WITH written AS ({source} RETURNING \"{}\") SELECT 1 FROM written",
                keys[0]
            ),
            format!("{source} ON CONFLICT ({arbiter}) DO NOTHING"),
        ],
        ActionStatement::InsertOnConflictUpdate => {
            let update = format!(
                "{source} ON CONFLICT ({arbiter}) DO UPDATE SET \"{settable}\" = excluded.\"{settable}\""
            );
            [update.clone(), update]
        }
        _ => return None,
    };

    let payload = serde_json::Value::Object(probe).to_string();
    let answers: Vec<bool> = spellings
        .iter()
        .map(|sql| attempt_write(conn, attempt, sql, &payload, raised))
        .collect();
    assert_eq!(
        answers[0], answers[1],
        "{}: two spellings of {statement:?} on {} answered differently, so one relation \
         cannot cover both",
        case.name, object.name
    );
    Some(answers[0])
}

/// Run one write spelling as the caller and roll it back, reading a refusal as a denial.
fn attempt_write(
    conn: &mut PgConnection,
    attempt: &Attempt,
    sql: &str,
    payload: &str,
    raised: &mut bool,
) -> bool {
    let Attempt {
        case,
        principal,
        object,
        statement,
    } = *attempt;
    let outcome = conn.transaction::<(), diesel::result::Error, _>(|conn| {
        become_principal(conn, principal)?;
        diesel::sql_query(sql)
            .bind::<diesel::sql_types::Text, _>(payload)
            .execute(conn)?;
        // The probe is never kept, so the comparison that follows sees the seeded rows.
        Err(diesel::result::Error::RollbackTransaction)
    });
    match outcome {
        Err(diesel::result::Error::RollbackTransaction) => true,
        // A caller that set nothing the policy reads raises rather than being filtered,
        // exactly as a read does, and the write does not happen either way.
        Err(error) if principal.reads_an_unset_setting && reads_an_unset_setting(&error) => {
            *raised = true;
            false
        }
        Err(error) => {
            let rendered = error.to_string();
            assert!(
                rendered.contains("row-level security"),
                "{}: {statement:?} on {} failed for a reason other than row-level \
                 security: {rendered}",
                case.name,
                object.name
            );
            false
        }
        Ok(()) => unreachable!("the transaction body always rolls back"),
    }
}

/// A key value the seeded rows do not carry, in the column's own type.
///
/// The type has to be asked for rather than guessed from the JSON, which spells a `uuid`
/// and a `text` the same way and would hand `uuid` a value it refuses. A type the runner
/// cannot mint for declines the comparison rather than reporting a syntax error as a
/// policy denying the write.
fn fresh_key(
    conn: &mut PgConnection,
    table: &str,
    column: &str,
    current: &serde_json::Value,
) -> Option<serde_json::Value> {
    let kind: Instant = diesel::sql_query(format!(
        "SELECT format_type(atttypid, atttypmod) AS instant
         FROM pg_attribute WHERE attrelid = '{table}'::regclass AND attname = $1"
    ))
    .bind::<diesel::sql_types::Text, _>(column)
    .get_result(conn)
    .ok()?;
    match (kind.instant.as_str(), current) {
        // One digit is enough, and keeping the shape keeps the value valid.
        ("uuid", serde_json::Value::String(text)) => {
            let mut digits = text.chars();
            let first = digits.next()?;
            let fresh = if first == 'f' { 'e' } else { 'f' };
            Some(serde_json::Value::String(
                core::iter::once(fresh).chain(digits).collect(),
            ))
        }
        ("text" | "character varying" | "name", serde_json::Value::String(text)) => {
            Some(serde_json::Value::String(format!("probe-{text}")))
        }
        ("integer" | "bigint" | "smallint", serde_json::Value::Number(number)) => {
            Some(serde_json::Value::from(number.as_i64()? + 1_000_000))
        }
        _ => None,
    }
}

/// Refuse a case where every compared pair got the same answer.
///
/// A generated case has no hand-written expectations, so agreement alone is weak: a model
/// granting everything agrees with a seed nothing denies. Requiring both answers is what
/// makes the generator's cases two sided by construction rather than by inspection.
pub(crate) fn assert_two_sided(case: &ParityCase, run: &Run) {
    let granted = run
        .observations
        .iter()
        .filter(|observation| observation.postgres)
        .count();
    assert!(
        granted > 0 && granted < run.compared(),
        "{}: the database answered the same way {} times out of {}, so a model granting \
         or denying everything would pass",
        case.name,
        granted.max(run.compared() - granted),
        run.compared()
    );
}

/// The case's declared changes, keyed the way an object names its table.
///
/// A case spells a table the way its schema does, `notes`, while an object carries
/// `TableId::sql_name`, `"public"."notes"`. Comparing those as text finds nothing, so the
/// spelling is resolved through the identities the model already named. A declaration
/// matching no table is a typo in the case, and silently disabling it would look like the
/// write simply not being compared.
fn resolved_mutations<'case>(
    case: &'case ParityCase,
    naming: &[RowNaming],
) -> BTreeMap<String, &'case Mutations> {
    let mut resolved = BTreeMap::new();
    for (spelling, mutations) in &case.mutations {
        let matches: Vec<&RowNaming> = naming
            .iter()
            .filter(|entry| names_the_same_table(&entry.table, spelling))
            .collect();
        let entry = match matches.as_slice() {
            [entry] => *entry,
            [] => panic!(
                "{}: no table the model names is spelled '{spelling}', so its declared \
                 change would never be attempted",
                case.name
            ),
            several => panic!(
                "{}: '{spelling}' names {} of the tables the model names, so which change \
                 is attempted would be arbitrary",
                case.name,
                several.len()
            ),
        };
        assert!(
            resolved.insert(entry.table.sql_name(), mutations).is_none(),
            "{}: two declarations resolve to '{}', and the second would win",
            case.name,
            entry.table.sql_name()
        );
    }
    resolved
}

/// Whether `spelling` names `table`, however the case wrote it.
///
/// One resolver, because comparing table names as text has three answers here: the stored
/// name, the qualified name, and the same name with the implicit schema spelled out. A
/// table stored without a schema resides in `public`, so `notes`, `public.notes` and
/// `"public"."notes"` are one table and have to resolve alike.
fn names_the_same_table(table: &TableId, spelling: &str) -> bool {
    if table.name() == spelling || table.to_string() == spelling || table.sql_name() == spelling {
        return true;
    }
    let (schema, name) = match unquote(spelling).split_once('.') {
        Some((schema, name)) => (unquote(schema).to_string(), unquote(name).to_string()),
        None => return false,
    };
    table.schema().unwrap_or("public") == schema && table.name() == name
}

/// One identifier with its quotes removed, which is not an unquoting of embedded ones.
fn unquote(spelling: &str) -> &str {
    spelling.trim_matches('"')
}

/// The sentences of a set of disclosures, for a failure that has to show them.
fn sentences(disclosures: &[Disclosure]) -> String {
    disclosures
        .iter()
        .map(|disclosure| disclosure.text.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

/// What one diverging note licenses, and where.
///
/// Read off the note's own fields rather than its prose. The direction is the note's
/// meaning, not its severity: a dropped clause can only narrow, while a guard left to the
/// caller and a membership table the loader reads as owner both widen, so severity alone
/// would license the wrong direction for half of them.
fn licence_of(note: &TranslationNote) -> Disclosure {
    let licence = match note {
        // A clause the threshold dropped, and the commands it fed. The machine readable
        // channel exists for exactly this.
        TranslationNote::ClauseBelowThreshold {
            table, commands, ..
        }
        | TranslationNote::CoveringPoliciesBelowThreshold { table, commands } => Licence::Located {
            table: table.sql_name(),
            commands: commands.clone(),
            direction: Direction::Narrower,
        },

        // Two that widen and cannot be placed. The membership table's own security decides
        // which rows a caller sees while the loader reads them as the owner, and it names
        // that table rather than the guarded one. The hybrid leaves its attribute guard to
        // the caller and names only its policy.
        TranslationNote::MembershipTableGuarded { .. }
        | TranslationNote::AttributeNeedsRuntimeEnforcement { .. } => Licence::Anywhere {
            direction: Direction::Wider,
        },
        // NULL rows fall closed. Names its policy alone.
        TranslationNote::NullableBooleanFlagNarrowed { .. } => Licence::Anywhere {
            direction: Direction::Narrower,
        },
        // Three that narrow and name their table: the parent reads its own rows only, so
        // its children's fall closed on that type, and an expression nobody classified
        // denies what the database may grant.
        TranslationNote::InheritanceParentReadsOwnRowsOnly { table, .. }
        | TranslationNote::BridgeColumnMissing { table, .. }
        | TranslationNote::RowsCannotBeNamed { table, .. } => Licence::Located {
            table: table.sql_name(),
            commands: Vec::new(),
            direction: Direction::Narrower,
        },
        other if other.severity() == NoteSeverity::Unhandled => Licence::Anywhere {
            direction: Direction::Narrower,
        },
        // A note this has not read licenses nothing: the point of the property is that
        // nothing diverges unnoticed.
        other => panic!(
            "a diverging note this property cannot read licenses nothing: {other}\n\
             give it a licence, or the divergence it stands for is excused everywhere"
        ),
    };
    Disclosure {
        text: note.to_string(),
        licence,
    }
}

/// Fail unless every disagreement sits where a note puts it and goes the way it says.
///
/// The property a disclosed case is held to. Requiring merely that *some* note exists
/// let one dropped clause excuse a mismatch anywhere in the schema, which is the hole
/// this closes: a note names a table and the commands it fed, and a mismatch elsewhere is
/// unlicensed however loudly the case discloses something else.
pub(crate) fn assert_disclosed_where_noted(case: &ParityCase, run: &Run) {
    let unlicensed: Vec<String> = run
        .mismatches()
        .into_iter()
        .filter(|mismatch| !licensed(mismatch, &run.disclosures))
        .map(ToString::to_string)
        .collect();
    assert!(
        unlicensed.is_empty(),
        "{}: no note puts a divergence here, or it goes the other way:\n{}\ndisclosed:\n{}",
        case.name,
        unlicensed.join("\n"),
        sentences(&run.disclosures)
    );
    assert!(
        run.compared() > 0,
        "{}: nothing was compared, so disclosure means nothing",
        case.name
    );
}

/// Whether some note licenses this disagreement.
///
/// A widening needs a note that names the table. Three notes widen without naming one, and
/// honouring those anywhere would accept every over-grant in the case, which is what the
/// property this replaces at least refused. Placing them means carrying the guarded table on
/// the note, so until then a widening they stand for fails and says so.
fn licensed(mismatch: &Mismatch, disclosures: &[Disclosure]) -> bool {
    let direction = if mismatch.openfga {
        Direction::Wider
    } else {
        Direction::Narrower
    };
    disclosures
        .iter()
        .any(|disclosure| match &disclosure.licence {
            Licence::Anywhere { direction: allowed } => {
                *allowed == direction && direction == Direction::Narrower
            }
            Licence::Located {
                table,
                commands,
                direction: allowed,
            } => {
                *allowed == direction
                    && *table == mismatch.table
                    && (commands.is_empty()
                        || commands
                            .iter()
                            .any(|command| statement_reads(mismatch.statement, command)))
            }
        })
}

/// Whether a policy on `command` decides `statement`.
///
/// `PostgreSQL`'s rule, and the generator's: a per-row `UPDATE` or `DELETE` names the row it
/// changes, so the `SELECT` policies apply and those relations intersect the read. A dropped
/// `SELECT` clause therefore explains a narrower write as well. A blanket `UPDATE` names no
/// row and reads nothing, so it stays `UPDATE` alone. A locking read applies the `UPDATE`
/// policies on top of the `SELECT` ones, and every `INSERT` shape is decided by the `INSERT`
/// policy, with the readback and the upsert adding what they read back.
fn statement_reads(statement: ActionStatement, command: &str) -> bool {
    match statement {
        ActionStatement::Select => command == "SELECT",
        ActionStatement::SelectForUpdate | ActionStatement::Update => {
            command == "SELECT" || command == "UPDATE"
        }
        ActionStatement::Delete => command == "SELECT" || command == "DELETE",
        ActionStatement::UpdateWithoutWhere => command == "UPDATE",
        ActionStatement::Insert => command == "INSERT",
        ActionStatement::InsertReturning => command == "INSERT" || command == "SELECT",
        ActionStatement::InsertOnConflictUpdate => {
            command == "INSERT" || command == "SELECT" || command == "UPDATE"
        }
        _ => false,
    }
}
