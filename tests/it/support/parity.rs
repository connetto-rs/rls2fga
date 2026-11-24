//! One runner for every `PostgreSQL` and `OpenFGA` parity case.
//!
//! A case declares data: a schema, a seed, the principals and the rows a write would
//! attempt. Which relations answer which statement, and how a row is named as an object,
//! come from the translation itself, so no case repeats that analysis.
//!
//! The comparison is the full cross product of principal, object and statement, in both
//! directions, so a case cannot check only the pairs its author thought of.

use core::ops::ControlFlow;
use core::time::Duration;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use diesel::connection::SimpleConnection;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::sql_types::Jsonb;
use sql_values::postgres::{InputContext, PgTimeZone, PgTimestampTz};
use sqlparser::ast::{visit_expressions, AssignmentTarget, Expr, Ident, Statement};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;
use testcontainers::{ContainerAsync, GenericImage};

use rls2fga::classifier::function_registry::{DeclaredSource, DeclaredSources};
use rls2fga::json_row;
use rls2fga::parser::sql_parser::SessionSetting;
use rls2fga::types::{
    records_from_row, ActionAnswer, ActionRelations, ActionStatement, ColumnCommand, ColumnName,
    ConfidenceLevel, NoteSeverity, Record, RecordDescription, RecordError, RequestAtom,
    RequestComparison, RequestPredicate, RowDecision, RowNaming, RowVersion, TableId,
    TranslationNote, ValueSource,
};

use super::openfga;

diesel::define_sql_function! {
    /// `PostgreSQL`'s `current_setting(setting_name)`.
    fn current_setting(setting: diesel::sql_types::Text) -> diesel::sql_types::Text;
}

/// One caller, on both sides.
///
/// Nothing in the translation says which database role a subject is, which session values
/// it sets, or which roles it holds, so a case says.
pub(crate) struct Principal {
    /// Subject key, naming the caller in every answer and unique within a case.
    pub(crate) subject: String,
    /// The user the caller acts for, asked about as `user:<user>`, its subject unless one
    /// user acts as two callers.
    pub(crate) user: String,
    /// Role the reading transaction switches to.
    pub(crate) login_role: String,
    /// `set_config` values the policies read, applied local to the transaction.
    pub(crate) session: Vec<(String, String)>,
    /// Request context every check carries.
    pub(crate) context: serde_json::Value,
    /// Whether every check carries the database's clock as `request_time`.
    pub(crate) carries_request_time: bool,
    /// Whether a policy raises on a setting this caller never set.
    ///
    /// A caller holding no token is in that state and reads nothing, so the raise is a
    /// denial. Declared per caller, because everywhere else a read that raises is a case
    /// granting no privilege or naming no column.
    pub(crate) reads_an_unset_setting: bool,
    /// Whether a policy raises parsing this caller's document as `JSON`.
    ///
    /// A document that is not `JSON` raises where the read reaches it, and the read
    /// returns no row, so the raise is a denial. Declared per caller, for the same reason
    /// an unset setting is.
    pub(crate) reads_a_non_json_document: bool,
}

impl Principal {
    /// A caller identified by one session setting, the ordinary shape.
    pub(crate) fn with_setting(subject: &str, login_role: &str, key: &str, value: &str) -> Self {
        Self {
            subject: subject.to_string(),
            user: subject.to_string(),
            login_role: login_role.to_string(),
            session: vec![(key.to_string(), value.to_string())],
            context: serde_json::json!({}),
            carries_request_time: false,
            reads_an_unset_setting: false,
            reads_a_non_json_document: false,
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
            user: subject.to_string(),
            login_role: login_role.to_string(),
            session: Vec::new(),
            context: serde_json::json!({}),
            carries_request_time: false,
            reads_an_unset_setting: false,
            reads_a_non_json_document: false,
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

    /// The same caller, asked about as `user:<user>`, for one user acting as two callers
    /// such as directly and through an installation.
    pub(crate) fn acting_for(mut self, user: &str) -> Self {
        self.user = user.to_string();
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

    /// The same caller, whose read raises because a policy reads a setting it never set.
    pub(crate) fn reading_an_unset_setting(mut self) -> Self {
        self.reads_an_unset_setting = true;
        self
    }

    /// The same caller, whose read raises because a policy parses a document it holds as
    /// `JSON`.
    pub(crate) fn reading_a_non_json_document(mut self) -> Self {
        self.reads_a_non_json_document = true;
        self
    }
}

/// Whether a caller acting as `acting_role` with `context` satisfies a predicate the request
/// alone decides.
pub(crate) fn request_predicate_holds(
    predicate: &RequestPredicate,
    context: &serde_json::Value,
    acting_role: &str,
) -> bool {
    match predicate {
        RequestPredicate::Holds(atom) => {
            if atom.fallback.is_empty() {
                match atom.comparison {
                    RequestComparison::CallerSetHolds => context[atom.request_parameter.as_str()]
                        .as_array()
                        .is_some_and(|set| set.iter().any(|entry| entry == atom.value.as_str())),
                    RequestComparison::CallerValueEquals => {
                        context["settings"][atom.request_parameter.as_str()] == atom.value.as_str()
                    }
                    // The absent key reads as `NULL`, which is no inequality either.
                    RequestComparison::CallerValueUnequals => context["settings"]
                        .get(atom.request_parameter.as_str())
                        .is_some_and(|stored| *stored != atom.value.as_str()),
                }
            } else {
                request_fallback_holds(atom, context)
            }
        }
        // An empty value is the `''` the `NULLIF` read reads as `NULL`.
        RequestPredicate::Carries { request_parameter } => context["settings"]
            .get(request_parameter.as_str())
            .is_some_and(|value| value != ""),
        RequestPredicate::Omits { request_parameter } => context["settings"]
            .get(request_parameter.as_str())
            .is_none_or(|value| value == ""),
        RequestPredicate::ActsAs { role } => role == acting_role,
        RequestPredicate::Any(children) => children
            .iter()
            .any(|child| request_predicate_holds(child, context, acting_role)),
        RequestPredicate::All(children) => children
            .iter()
            .all(|child| request_predicate_holds(child, context, acting_role)),
    }
}

/// The answer the model gives on the value a fallback read hands over, walking the
/// sources in the order the policy reads them.
///
/// A source wrapped in `NULLIF` skips its value on the empty one and on the absent key,
/// and a source without the wrap, and every source of a field, stops the walk on the
/// absent key, where the model reads `NULL`.
fn request_fallback_holds(atom: &RequestAtom, context: &serde_json::Value) -> bool {
    let settings = &context["settings"];
    for step in &atom.fallback {
        match settings
            .get(&step.parameter)
            .and_then(serde_json::Value::as_str)
        {
            Some(value) if !(step.skips_empty && !step.from_json_field && value.is_empty()) => {
                // The walk lands on the value the source hands over, tested as the
                // comparison spells it.
                return match atom.comparison {
                    RequestComparison::CallerValueEquals => value == atom.value.as_str(),
                    _ => value != atom.value.as_str(),
                };
            }
            Some(_) | None if step.skips_empty && !step.from_json_field => {}
            _ => return false,
        }
    }
    false
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
    /// Per table, keyed by the schema spelling, the `SET` clause an `UPDATE` probe applies,
    /// such as `title = 'changed'`. A table without one is probed with a no-op assignment.
    pub(crate) update_sets: BTreeMap<String, String>,
    /// Per table, what an `INSERT` probe writes beyond the row it copies.
    pub(crate) inserting: BTreeMap<String, Inserting>,
    /// Clause sides no seed can show, each with the reason, which the per-clause check
    /// skips and fails on where they turn out to be shown.
    pub(crate) unobservable: Vec<Unobservable>,
    /// Accessor metadata the deployment declares, as a fixture's
    /// `function_registry.json` holds it.
    pub(crate) registry_json: Option<String>,
    /// Settings the deployment declares beside the suite's callers, as a fixture's
    /// `deployment.json` holds them.
    pub(crate) settings: Vec<SessionSetting>,
    /// The access attributes the policies compare, confirmed as `(table, column)` pairs.
    ///
    /// A literal check on an unconfirmed column grades below `A`, so the case confirms the
    /// columns the schema's own registry confirms, and the translation holds to its
    /// declared class with them confirmed the way the schema declares them.
    pub(crate) attribute_columns: Vec<(String, String)>,
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
    /// The `TimeZone` the schema is created in, which `PostgreSQL` reads the policies'
    /// date and time literals in. `None` leaves the server's and tells rls2fga no zone.
    pub(crate) session_time_zone: Option<String>,
    /// The `lc_monetary` the schema is created in, which `PostgreSQL` parses its `money`
    /// literals by. Declared to rls2fga too, so its tuple queries set it.
    pub(crate) monetary_locale: Option<String>,
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
            update_sets: BTreeMap::new(),
            inserting: BTreeMap::new(),
            unobservable: Vec::new(),
            registry_json: None,
            settings: Vec::new(),
            attribute_columns: Vec::new(),
            not_read_directly: Vec::new(),
            loading_from_rows: false,
            future: None,
            session_time_zone: None,
            monetary_locale: None,
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

    /// The same case, its schema created in a session whose `TimeZone` is `zone`.
    pub(crate) fn created_in_time_zone(mut self, zone: &str) -> Self {
        self.session_time_zone = Some(zone.to_string());
        self
    }

    /// The same case, its schema created in, and declared as written in, `locale`'s
    /// `lc_monetary`.
    pub(crate) fn created_in_monetary_locale(mut self, locale: &str) -> Self {
        self.monetary_locale = Some(locale.to_string());
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
        case.settings =
            std::fs::read_to_string(super::fixture_dir(fixture).join("deployment.json"))
                .map_or_else(
                    |_| Vec::new(),
                    |json| super::deployment::settings_from_json(&json),
                );
        case
    }

    /// The same case, with the accessor metadata its deployment declares.
    pub(crate) fn with_registry(mut self, registry_json: &str) -> Self {
        self.registry_json = Some(registry_json.to_string());
        self
    }

    /// The same case, its deployment declaring `settings` beside the suite's callers.
    pub(crate) fn with_settings(
        mut self,
        settings: impl IntoIterator<Item = SessionSetting>,
    ) -> Self {
        self.settings = settings.into_iter().collect();
        self
    }

    /// The same case, confirming `columns` as the access attributes its policies compare.
    pub(crate) fn with_attribute_columns(mut self, columns: &[(&str, &str)]) -> Self {
        self.attribute_columns = columns
            .iter()
            .map(|(table, column)| (table.to_string(), column.to_string()))
            .collect();
        self
    }

    /// The roles the deployment acts as, each role a caller runs as, in the order the
    /// callers are listed.
    pub(crate) fn acting_roles(&self) -> Vec<&str> {
        let mut roles: Vec<&str> = Vec::new();
        for principal in &self.principals {
            if !roles.contains(&principal.login_role.as_str()) {
                roles.push(&principal.login_role);
            }
        }
        roles
    }

    /// The same case, reading the named tables only through the table that types them.
    pub(crate) fn not_reading_directly(mut self, tables: &[&str]) -> Self {
        self.not_read_directly = tables.iter().map(|table| (*table).to_string()).collect();
        self
    }

    /// The same case, whose `UPDATE` probes on `table` apply `set`.
    pub(crate) fn updating(mut self, table: &str, set: &str) -> Self {
        self.update_sets.insert(table.to_string(), set.to_string());
        self
    }

    /// The same case, whose `INSERT` probes on `table` write `values` in place of the copied
    /// or minted ones, for a policy arm that admits one key alone.
    pub(crate) fn inserting_values(mut self, table: &str, values: &[(&str, &str)]) -> Self {
        self.inserting.entry(table.to_string()).or_default().values = values
            .iter()
            .map(|(column, value)| ((*column).to_string(), (*value).to_string()))
            .collect();
        self
    }

    /// The same case, declaring that no seed can show `side` of `policy`'s `clause` on
    /// `table`, for `reason`.
    ///
    /// For a side whose every case is already decided elsewhere, such as an `UPDATE`
    /// policy's `USING` repeating the `SELECT` policy's, which every `UPDATE` also applies.
    pub(crate) fn unobservable(
        mut self,
        table: &str,
        policy: &str,
        clause: ClauseKind,
        side: Side,
        reason: &str,
    ) -> Self {
        assert!(
            !reason.trim().is_empty(),
            "{}: a waiver needs its reason",
            self.name
        );
        self.unobservable.push(Unobservable {
            table: table.to_string(),
            policy: policy.to_string(),
            clause,
            side,
            reason: reason.to_string(),
        });
        self
    }

    /// The same case, whose `INSERT` probes on `table` name only `columns`, the ones its
    /// column privileges let a caller insert, and leave the rest to their defaults.
    pub(crate) fn inserting_columns(mut self, table: &str, columns: &[&str]) -> Self {
        self.inserting.entry(table.to_string()).or_default().columns =
            Some(columns.iter().map(|column| (*column).to_string()).collect());
        self
    }
}

/// What a case's `INSERT` probes on one table write beyond the row they copy.
#[derive(Clone, Default)]
pub(crate) struct Inserting {
    /// Values written in place of the copied or minted ones, as `(column, text)` pairs.
    pub(crate) values: Vec<(String, String)>,
    /// The columns the statement names, every column the table does not generate where
    /// `None`.
    pub(crate) columns: Option<Vec<String>>,
}

/// Which clause of a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClauseKind {
    /// `USING`.
    Using,
    /// The `USING` expression of an `ALL` or `UPDATE` policy without `WITH CHECK`, which
    /// checks the new row too.
    UsingAsCheck,
    /// `WITH CHECK`.
    Check,
}

impl std::fmt::Display for ClauseKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Using => "USING",
            Self::UsingAsCheck => "USING as WITH CHECK",
            Self::Check => "WITH CHECK",
        })
    }
}

/// Which way a clause's value decides an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Side {
    /// The clause being true grants.
    Grants,
    /// The clause being false denies.
    Denies,
}

impl std::fmt::Display for Side {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Grants => "grant side",
            Self::Denies => "deny side",
        })
    }
}

/// One clause side a case declares no seed can show.
pub(crate) struct Unobservable {
    /// The table, as the schema spells it, bare or schema-qualified.
    table: String,
    policy: String,
    clause: ClauseKind,
    side: Side,
    /// Why no seed can show it.
    reason: String,
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
    /// What the row recipes answered, [`None`] where they leave the pair to the model.
    pub(crate) local: Option<bool>,
}

impl Mismatch {
    /// Whether the two sides answered differently.
    pub(crate) fn disagrees(&self) -> bool {
        self.postgres != self.openfga
    }
}

/// What the database answered, and the row the write produces where the probe knows it.
struct ProbeResult {
    /// What the probe measured.
    postgres: bool,
    /// The row the write produces, absent where the table's own integrity refuses that row
    /// even to its owner.
    produced: Option<serde_json::Value>,
}

/// Everything one case observed.
#[derive(Debug)]
pub(crate) struct Run {
    /// Every compared pair, in the order the runner walked them.
    pub(crate) observations: Vec<Mismatch>,
    /// What the translation said diverges, each with what it licenses.
    pub(crate) disclosures: Vec<Disclosure>,
    /// The clause sides the case left undecided.
    coverage: Coverage,
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
            "user:{} {:?} {}: postgres={}, openfga={}, local={:?}",
            self.subject, self.statement, self.object, self.postgres, self.openfga, self.local
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

#[derive(QueryableByName)]
struct Column {
    #[diesel(sql_type = diesel::sql_types::Text)]
    name: String,
}

#[derive(QueryableByName)]
struct ConstraintHit {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    one: i32,
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
    /// The table's columns a statement may assign, in the table's own order.
    ///
    /// A generated or always-identity column the database computes cannot be named by a
    /// probe's column list or `SET` clause, which would fail before row-level security
    /// decides.
    non_generated: Vec<String>,
    /// One permission object shared by every row.
    singleton: bool,
    /// What the case's `INSERT` probes on the table write beyond this row.
    inserting: Option<Inserting>,
    /// The `SET` clause the `UPDATE` probe applies, [`None`] where the table has no column
    /// to assign.
    update_set: Option<String>,
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

/// The `WHERE` clause naming one row by its key, compared as `to_jsonb` printed it so any
/// key type fits, a blank-padded `char(n)` included.
fn key_predicate(row: &serde_json::Value, columns: &[&str]) -> String {
    let mut predicate = String::new();
    for (at, column) in columns.iter().enumerate() {
        let value = row
            .get(*column)
            .unwrap_or(&serde_json::Value::Null)
            .to_string();
        let joiner = if at == 0 { "" } else { " AND " };
        let _ = write!(
            predicate,
            "{joiner}to_jsonb(\"{column}\") = '{}'::jsonb",
            value.replace('\'', "''")
        );
    }
    predicate
}

/// Every object the model names, read as the owner so row-level security does not filter
/// the enumeration.
fn objects(
    conn: &mut PgConnection,
    naming: &[RowNaming],
    skipped: &[String],
    inserting: &BTreeMap<String, &Inserting>,
    update_sets: &BTreeMap<String, &String>,
) -> Vec<Object> {
    let mut out = Vec::new();
    for entry in naming {
        if skipped.iter().any(|table| entry.table.name() == table) {
            continue;
        }
        let singleton = !entry.key.parts().is_empty()
            && entry
                .key
                .parts()
                .iter()
                .all(|part| matches!(part, ValueSource::Literal(_)));
        let Some(columns) = key_columns(entry).or_else(|| singleton.then(Vec::new)) else {
            panic!(
                "{}: its objects are named by something other than its columns, so no \
                 probe can select one and every pair on it would go uncompared",
                entry.table.sql_name()
            )
        };
        let table = entry.table.sql_name();
        let inserting = inserting.get(&table).map(|declared| (*declared).clone());
        let declared_set = update_sets.get(&table).map(|set| (*set).clone());
        let limit = if singleton { " LIMIT 1" } else { "" };
        // Case tables and columns are defined at runtime, and the probe may assign only
        // the columns `PostgreSQL` does not compute itself.
        let non_generated: Vec<String> = diesel::sql_query(format!(
            "SELECT attname AS name FROM pg_attribute
             WHERE attrelid = '{table}'::regclass AND attnum > 0 AND NOT attisdropped
               AND attgenerated = '' AND attidentity <> 'a'
             ORDER BY attnum"
        ))
        .load::<Column>(conn)
        .unwrap_or_else(|error| panic!("reading the columns of {table}: {error}"))
        .into_iter()
        .map(|Column { name }| name)
        .collect();
        // Case tables and columns are defined at runtime.
        let rows: Vec<JsonRow> =
            diesel::sql_query(format!("SELECT to_jsonb(t) AS row FROM {table} t{limit}"))
                .load(conn)
                .unwrap_or_else(|error| panic!("reading {table} as its owner: {error}"));
        if singleton {
            let row = rows
                .into_iter()
                .next()
                .map_or_else(|| serde_json::json!({}), |value| value.row);
            let name = entry
                .render(&json_row::JsonRow(&row))
                .expect("the fixed object name is valid")
                .expect("a literal key names the permission object");
            let update_set = declared_set.or_else(|| no_op_set(&non_generated, &[]));
            out.push(Object {
                name,
                table,
                predicate: "TRUE".to_string(),
                row,
                keys: Vec::new(),
                non_generated: non_generated.clone(),
                singleton,
                inserting: None,
                update_set,
            });
            continue;
        }
        for JsonRow { row } in rows {
            // A name the renderer refuses is the row-naming divergence this suite exists to
            // find, so it fails here rather than removing the row and passing on the rest.
            // `Ok(None)` is the deliberate one: no column names that row.
            let name = match entry.render(&json_row::JsonRow(&row)) {
                Ok(Some(name)) => name,
                Ok(None) => continue,
                Err(error) => panic!("naming a row of {table}: {error}"),
            };

            let predicate = key_predicate(&row, &columns);
            let update_set = declared_set
                .clone()
                .or_else(|| no_op_set(&non_generated, &columns));
            out.push(Object {
                name,
                table: table.clone(),
                predicate,
                row,
                keys: columns.iter().map(|column| (*column).to_string()).collect(),
                non_generated: non_generated.clone(),
                singleton,
                inserting: inserting.clone(),
                update_set,
            });
        }
    }
    out
}

/// An assignment of a column to itself, which changes no value, so an `UPDATE` probe
/// without a declared change still asks the `USING` clauses and the check about the row
/// as it stands.
fn no_op_set(columns: &[String], keys: &[&str]) -> Option<String> {
    let column = assignable_column(columns, keys)?;
    Some(format!("\"{column}\" = \"{column}\""))
}

/// The columns the probe for `statement` on `object` names, those the case declares for
/// its inserts, or else every column the database does not compute itself.
fn listed_columns(object: &Object, statement: ActionStatement) -> &[String] {
    match (&object.inserting, statement) {
        (
            Some(Inserting {
                columns: Some(columns),
                ..
            }),
            ActionStatement::Insert | ActionStatement::InsertReturning,
        ) => columns,
        _ => &object.non_generated,
    }
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
/// next. [`None`] only where the statement cannot be written on the table at all, so no
/// pair exists.
fn postgres_allows(
    conn: &mut PgConnection,
    case: &ParityCase,
    principal: &Principal,
    object: &Object,
    statement: ActionStatement,
    // Set where a read raised because the caller set nothing, asked once per caller.
    raised: &mut bool,
) -> Option<ProbeResult> {
    let table = &object.table;
    let predicate = &object.predicate;
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
            let set = object.update_set.as_deref()?;
            format!("WITH changed AS (UPDATE {table} SET {set} WHERE {predicate} RETURNING 1) SELECT count(*) AS rows FROM changed")
        }
        ActionStatement::Delete => format!(
            "WITH removed AS (DELETE FROM {table} WHERE {predicate} RETURNING 1) SELECT count(*) AS rows FROM removed"
        ),
        _ => unreachable!("{statement:?} is not a compared statement"),
    };

    // Always rolled back: a `DELETE` the caller may run would otherwise take the row away
    // from every caller compared after it, and the answers would depend on their order.
    let mut granted = false;
    let answered = match conn.transaction::<(), diesel::result::Error, _>(|conn| {
        become_principal(conn, principal)?;
        let counted: Counted = diesel::sql_query(&sql).get_result(conn)?;
        granted = object.singleton || counted.rows == 1;
        Err(diesel::result::Error::RollbackTransaction)
    }) {
        Err(diesel::result::Error::RollbackTransaction) => Ok(granted),
        Err(error) => Err(error),
        Ok(()) => unreachable!("the transaction body always rolls back"),
    };
    // Reads mint no row, so only the measured answer leaves this path.
    let postgres = match answered {
        // Not asserted per read: `PostgreSQL` may settle a correlated EXISTS from the join
        // alone and never evaluate the accessor, so a row no membership row mentions is
        // denied without raising. Whether the claim still holds is asked once per caller,
        // which is a question about the caller rather than about the planner's order.
        Ok(granted) => granted,
        // Row-level security raises on exactly one thing when reading: a policy that
        // expands into itself. The read returns no row, so it is a denial, and the model
        // has to deny too.
        Err(error) if reads_as_a_policy_refusal(&error) => false,
        // A caller that set nothing the policy reads is denied, where the case says so.
        Err(error) if principal.reads_an_unset_setting && reads_an_unset_setting(&error) => {
            *raised = true;
            false
        }
        // A document that is not `JSON` raises where the read reaches it, which is a
        // denial, where the case says so.
        Err(error) if principal.reads_a_non_json_document && reads_a_non_json_document(&error) => {
            *raised = true;
            false
        }
        // A caller without the table's privilege raises `42501`, which is a denial, and the
        // model has to deny too.
        Err(error) if lacks_a_table_privilege(&error) => false,
        // Otherwise a plain read never raises, so an error is a case that named no column,
        // and calling it a denial would hide the mistake.
        Err(error) if statement == ActionStatement::Select => panic!(
            "{}: reading {table} as {} raised, which row-level security never does: {error}",
            case.name, principal.login_role
        ),
        // A write the policy admits meets the table's own declared integrity when the
        // statement itself breaks one, and the probe reads that as allowed.
        Err(error) if is_constraint_violation(&error) => {
            if declared_constraint_block(conn, &error, table, statement) {
                true
            } else {
                panic!(
                    "{}: {statement:?} on {table} raised a constraint error the table does \
                     not declare: {error}",
                    case.name
                )
            }
        }
        // A write the check refuses raises, and that is a denial.
        Err(_) => false,
    };
    let produced = match (statement, object.update_set.as_deref()) {
        (ActionStatement::Update, Some(set)) => updated_row(conn, case, table, set, predicate),
        _ => None,
    };
    Some(ProbeResult { postgres, produced })
}

/// The row an `UPDATE` applying `set` to the row `predicate` names produces, written as the
/// connection's own role, which no policy filters, and rolled back. [`None`] where no row
/// matches or the table's own integrity refuses the change, so no row results.
fn updated_row(
    conn: &mut PgConnection,
    case: &ParityCase,
    table: &str,
    set: &str,
    predicate: &str,
) -> Option<serde_json::Value> {
    let mut produced = None;
    match conn.transaction::<(), diesel::result::Error, _>(|conn| {
        let rows: Vec<JsonRow> = diesel::sql_query(format!(
            "UPDATE {table} AS written SET {set} WHERE {predicate} RETURNING to_jsonb(written) AS row"
        ))
        .load(conn)?;
        produced = rows.into_iter().next().map(|JsonRow { row }| row);
        Err(diesel::result::Error::RollbackTransaction)
    }) {
        Err(diesel::result::Error::RollbackTransaction) => produced,
        Err(error) if is_constraint_violation(&error) => None,
        Err(error) => panic!("{}: updating {table} as its owner: {error}", case.name),
        Ok(()) => unreachable!("the transaction body always rolls back"),
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

/// Whether `error` is a policy parsing a value that is not a `JSON` document, `22P02`.
fn reads_a_non_json_document(error: &diesel::result::Error) -> bool {
    matches!(error, diesel::result::Error::DatabaseError(_, info)
        if info.message().contains("invalid input syntax for type json"))
}

/// Match table-privilege denials without hiding column or function errors.
fn lacks_a_table_privilege(error: &diesel::result::Error) -> bool {
    matches!(error, diesel::result::Error::DatabaseError(_, info)
        if info.message().contains("permission denied for table"))
}

/// Whether `error` is the `23503` or `23514` a blocked write raises.
fn is_constraint_violation(error: &diesel::result::Error) -> bool {
    matches!(
        error,
        diesel::result::Error::DatabaseError(_, info)
            if info.sqlstate().is_some_and(|state| {
                state.as_str() == "23503" || state.as_str() == "23514"
            })
    )
}

/// Whether `error` is the declared integrity of `probed_table` refusing a copy the policy
/// already admitted, so the probe reads it as allowed rather than as the policy refusing:
/// the `23514` of a `CHECK` the table declares, or the `23503` of a foreign key the table
/// references or is referenced by.
///
/// The `PostgreSQL` fields the check matches are the error's own: the constraint it names
/// must be a real constraint on the table the error names, in the probed table's schema,
/// attached to the probed table on either side of the foreign key. A `DELETE` fires its
/// triggers only for rows its policy admitted, so for one the constraint may sit on any
/// table a trigger's writes reach. An `INSERT` or `UPDATE` fires its `BEFORE` triggers
/// before its `WITH CHECK`, so there the attachment stays required. A trigger that
/// `RAISE`s the same SQLSTATE names no constraint and stays a loud failure. The catalog
/// query is a raw `sql_query`, since the probed table is runtime data no `table!` can
/// type, and the `regclass` casts keep every name resolved in the case's own search path.
fn declared_constraint_block(
    conn: &mut PgConnection,
    error: &diesel::result::Error,
    probed_table: &str,
    statement: ActionStatement,
) -> bool {
    let diesel::result::Error::DatabaseError(_, info) = error else {
        return false;
    };
    let Some(state) = info.sqlstate() else {
        return false;
    };
    let contype = if state.as_str() == "23514" {
        "c"
    } else if state.as_str() == "23503" {
        "f"
    } else {
        return false;
    };
    let Some(constraint) = info.constraint_name() else {
        return false;
    };
    // Without the table the violation sits on the constraint cannot be matched, and the
    // unmatched code stays a loud failure.
    let Some(error_table) = info.table_name() else {
        return false;
    };
    diesel::sql_query(
        "SELECT 1 AS one FROM pg_constraint
         WHERE conname = $1
           AND conrelid = $2::regclass
           AND contype = $3
           AND ($5 OR conrelid = $4::regclass OR confrelid = $4::regclass)
           AND connamespace = (SELECT relnamespace FROM pg_class WHERE oid = $4::regclass)",
    )
    .bind::<diesel::sql_types::Text, _>(constraint)
    .bind::<diesel::sql_types::Text, _>(error_table)
    .bind::<diesel::sql_types::Text, _>(contype)
    .bind::<diesel::sql_types::Text, _>(probed_table)
    .bind::<diesel::sql_types::Bool, _>(statement == ActionStatement::Delete)
    .get_result::<ConstraintHit>(conn)
    .is_ok_and(|ConstraintHit { one }| one == 1)
}

/// The model under test, as the three things every question about it needs.
struct Model<'run> {
    client: &'run openfga::Client,
    answers: &'run [ActionRelations],
    /// The translation whose clock parameters a check carries.
    translation: &'run rls2fga::translator::Translation,
    /// For the case's name, which every refusal reports.
    case: &'run ParityCase,
    /// The `settings` map each principal's checks carry, by subject.
    settings: &'run BTreeMap<String, serde_json::Value>,
}

/// The clock parameters a check at `instant` carries, computed as a checker computes them
/// in the `TimeZone` `conn`'s session runs in.
fn clock_context(
    conn: &mut PgConnection,
    model: &Model<'_>,
    instant: &Instant,
) -> serde_json::Map<String, serde_json::Value> {
    let name = &model.case.name;
    let zone: String = diesel::select(current_setting("TimeZone"))
        .get_result(conn)
        .unwrap_or_else(|error| panic!("{name}: reading the session zone: {error}"));
    let zone = PgTimeZone::parse(&zone)
        .unwrap_or_else(|error| panic!("{name}: the session zone {zone}: {error}"));
    let at = PgTimestampTz::parse(&instant.instant, InputContext::new())
        .unwrap_or_else(|error| panic!("{name}: the instant {}: {error}", instant.instant));
    model
        .translation
        .clock_context(at, &zone)
        .unwrap_or_else(|error| panic!("{name}: the clock context: {error}"))
}

/// Whether `decision` grants `user` on `row` for a check carrying `context` and acting as
/// `acting_role`, [`None`] where a shape cannot read the row.
///
/// The consumer's whole evaluation, written from the contract alone.
pub(crate) fn decision_grants(
    decision: &RowDecision,
    row: &serde_json::Value,
    user: &str,
    context: &serde_json::Value,
    acting_role: &str,
) -> Option<bool> {
    let records = |shapes: &[RecordDescription]| -> Option<Vec<Record>> {
        let mut records = Vec::new();
        for shape in shapes {
            records.extend(records_from_row(shape, &json_row::JsonRow(row)).ok()?);
        }
        Some(records)
    };
    let children = |children: &[RowDecision]| -> Option<Vec<bool>> {
        children
            .iter()
            .map(|child| decision_grants(child, row, user, context, acting_role))
            .collect()
    };
    Some(match decision {
        RowDecision::Leaf { shapes, .. } => records(shapes)?
            .iter()
            .any(|record| record.subject == format!("user:{user}")),
        RowDecision::Everyone { shapes, .. } => !records(shapes)?.is_empty(),
        RowDecision::RequestGated { shapes, gate, .. } => records(shapes)?.iter().any(|record| {
            let row_side = &record
                .context
                .as_ref()
                .expect("a gated record carries its context")
                .values[&gate.context_key];
            let request_parameter = gate.request_parameter.as_str();
            // A set keeps its own list parameter the row tests membership in, and a
            // single value travels in the `settings` map under its parameter name.
            match gate.comparison {
                RequestComparison::CallerSetHolds => context[request_parameter]
                    .as_array()
                    .is_some_and(|held| held.iter().any(|value| value == row_side.as_str())),
                RequestComparison::CallerValueEquals => {
                    context["settings"][request_parameter] == row_side.as_str()
                }
                // The absent key reads as `NULL`, which is no inequality either.
                RequestComparison::CallerValueUnequals => context["settings"]
                    .get(request_parameter)
                    .is_some_and(|caller_side| caller_side != row_side.as_str()),
            }
        }),
        RowDecision::Request {
            shapes,
            subject_type,
            predicate,
            ..
        } => {
            subject_type.as_str() == "user"
                && !records(shapes)?.is_empty()
                && request_predicate_holds(predicate, context, acting_role)
        }
        RowDecision::Any(nested) => children(nested)?.into_iter().any(|granted| granted),
        RowDecision::All(nested) => children(nested)?.into_iter().all(|granted| granted),
    })
}

/// What the row recipes answer for `principal` on `object`, as a consumer holding the
/// changed row answers without asking the model, [`None`] where they leave it to the model.
///
/// A refusal on one judgement settles the pair whatever the others say, and rows passing
/// where columns are asked as well leave the columns to the model.
fn local_allows(
    model: &Model<'_>,
    principal: &Principal,
    context: &serde_json::Value,
    object: &Object,
    statement: ActionStatement,
    produced: Option<&serde_json::Value>,
) -> Option<bool> {
    let type_name = object
        .name
        .split_once(':')
        .map_or_else(|| object.name.as_str(), |(type_name, _)| type_name);
    let entry = model
        .answers
        .iter()
        .find(|entry| entry.type_name == *type_name && entry.statement == statement)?;
    let (rows, columns_asked) = match &entry.answer {
        ActionAnswer::ByColumn(answer) => (answer.rows.as_ref(), true),
        answer => (answer, false),
    };
    let judgements = match rows {
        ActionAnswer::Unrestricted => return (!columns_asked).then_some(true),
        ActionAnswer::Denied => return Some(false),
        ActionAnswer::Judged(judgements) if !judgements.is_empty() => judgements,
        _ => return None,
    };
    let mut settled = Some(true);
    for judgement in judgements {
        let row = match judgement.version {
            RowVersion::Resulting => produced,
            _ => Some(&object.row),
        };
        let granted = row.and_then(|row| {
            let decision = model
                .translation
                .relations()
                .iter()
                .find(|reported| {
                    reported.type_name == judgement.type_name
                        && reported.relation == judgement.relation
                })?
                .decision
                .as_ref()?;
            decision_grants(
                decision,
                row,
                &principal.user,
                context,
                &principal.login_role,
            )
        });
        match granted {
            Some(false) => return Some(false),
            Some(true) => {}
            None => settled = None,
        }
    }
    if columns_asked {
        None
    } else {
        settled
    }
}

/// Whether the model grants `principal` the statement on `object`.
///
/// `produced` is the row the write produces, which a `Resulting` judgement asks about
/// under the type the translation names for it, carrying that row's facts. A pair the
/// database answered is always answered here too, and a pair this cannot ask about fails
/// the case with the reason.
async fn openfga_allows(
    model: &Model<'_>,
    principal: &Principal,
    context: &serde_json::Value,
    object: &Object,
    statement: ActionStatement,
    produced: Option<&serde_json::Value>,
) -> bool {
    let Model {
        client,
        answers,
        translation,
        case,
        ..
    } = model;
    let principals = translation.request_principals();
    let type_name = object
        .name
        .split_once(':')
        .map_or_else(|| object.name.as_str(), |(type_name, _)| type_name);
    // Skipping a missing answer would let the remaining pairs satisfy the non-vacuity guard.
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
    let user = format!("user:{}", principal.user);
    let rows = match &entry.answer {
        ActionAnswer::ByColumn(answer) => {
            let touched = touched_columns(object, statement).unwrap_or_else(|| {
                panic!(
                    "{}: the database answered {statement:?} on {}, which the runner names \
                     no columns for",
                    case.name, object.name
                )
            });
            for relations in &answer.commands {
                for column in touched.of(relations.command) {
                    let granted = openfga::check_as(
                        client,
                        &principal.login_role,
                        principals,
                        &user,
                        relations.relation(column).as_str(),
                        &answer.gate,
                        context.clone(),
                        Vec::new(),
                    )
                    .await;
                    if !granted {
                        return false;
                    }
                }
            }
            answer.rows.as_ref()
        }
        answer => answer,
    };
    match rows {
        ActionAnswer::Unrestricted => true,
        ActionAnswer::Denied => false,
        ActionAnswer::Judged(judgements) => {
            for judgement in judgements {
                let (name, carried) = if judgement.version == RowVersion::Resulting {
                    let Some(row) = produced else {
                        panic!(
                            "{}: {statement:?} on {} as {} judges the row the write produces, \
                             and the table's own integrity refuses that row even to its \
                             owner, so the probe tests no policy",
                            case.name, object.name, principal.subject
                        )
                    };
                    let Some(resulting) = translation
                        .resulting_rows()
                        .iter()
                        .find(|resulting| resulting.type_name == judgement.type_name)
                    else {
                        panic!(
                            "{}: {statement:?} on '{type_name}' judges the written row on \
                             '{}', which the translation gives no way to name",
                            case.name, judgement.type_name
                        )
                    };
                    let values = json_row::JsonRow(row);
                    let name = match resulting.object(&values) {
                        Ok(Some(name)) => name,
                        Ok(None) => panic!(
                            "{}: the row {statement:?} writes on '{type_name}' names no object",
                            case.name
                        ),
                        // A checker that cannot name the written row cannot ask about it,
                        // so it refuses the write.
                        Err(RecordError::RowCannotBeNamed(_)) => return false,
                        Err(error) => panic!(
                            "{}: naming the row {statement:?} writes on '{type_name}': {error}",
                            case.name
                        ),
                    };
                    let carried = resulting
                        .records(&values)
                        .unwrap_or_else(|error| {
                            panic!(
                                "{}: the facts of the row {statement:?} writes on \
                                 '{type_name}': {error:?}",
                                case.name
                            )
                        })
                        .iter()
                        .map(openfga::record_tuple)
                        .collect();
                    (name, carried)
                } else {
                    (object.name.clone(), Vec::new())
                };
                let granted = openfga::check_as(
                    client,
                    &principal.login_role,
                    principals,
                    &user,
                    judgement.relation.as_str(),
                    &name,
                    context.clone(),
                    carried,
                )
                .await;
                if !granted {
                    return false;
                }
            }
            true
        }
        // Reading an unknown answer as no answer would drop the pair uncompared.
        other => panic!(
            "{}: the model answered {other:?} for {statement:?} on '{type_name}', which this \
             runner does not read yet",
            case.name
        ),
    }
}

/// The columns one probe statement touches, per command `PostgreSQL` checks on them.
#[derive(Default)]
struct Touched {
    select: BTreeSet<ColumnName>,
    insert: BTreeSet<ColumnName>,
    update: BTreeSet<ColumnName>,
}

impl Touched {
    /// The columns `command` is checked on.
    fn of(&self, command: ColumnCommand) -> &BTreeSet<ColumnName> {
        match command {
            ColumnCommand::Select => &self.select,
            ColumnCommand::Insert => &self.insert,
            ColumnCommand::Update => &self.update,
        }
    }
}

/// The columns the probe for `statement` on `object` touches, [`None`] where the statement
/// cannot be written on the table.
fn touched_columns(object: &Object, statement: ActionStatement) -> Option<Touched> {
    let keys = || object.keys.iter().map(ColumnName::from_stored);
    let listed = || {
        listed_columns(object, statement)
            .iter()
            .map(ColumnName::from_stored)
    };
    let mut touched = Touched::default();
    match statement {
        ActionStatement::Select | ActionStatement::SelectForUpdate | ActionStatement::Delete => {
            touched.select.extend(keys());
        }
        ActionStatement::Update => {
            (touched.update, touched.select) = set_columns(object.update_set.as_deref()?);
            touched.select.extend(keys());
        }
        ActionStatement::Insert => touched.insert.extend(listed()),
        ActionStatement::InsertReturning => {
            // Both spellings read the whole key, the arbiter as much as `RETURNING`.
            if object.keys.is_empty() {
                touched
                    .select
                    .insert(ColumnName::from_stored(assignable_column(
                        &object.non_generated,
                        &object.keys,
                    )?));
            } else {
                touched.select.extend(keys());
            }
            touched.insert.extend(listed());
        }
        ActionStatement::InsertOnConflictUpdate => {
            let settable = assignable_column(&object.non_generated, &object.keys)?;
            touched.insert.extend(listed());
            touched.update.insert(ColumnName::from_stored(settable));
            // The arbiter and the `excluded` column the update assigns are both read.
            touched.select.extend(keys());
            touched.select.insert(ColumnName::from_stored(settable));
        }
        _ => unreachable!("{statement:?} is not a compared statement"),
    }
    Some(touched)
}

/// The column a probe assigns or returns among `columns`, the first one outside the key the
/// probe replaces, or the first key column where every column is in the key.
fn assignable_column<'column>(
    columns: &'column [String],
    keys: &[impl AsRef<str>],
) -> Option<&'column str> {
    let first = columns.first()?;
    Some(
        columns
            .iter()
            .find(|column| !keys.iter().any(|key| key.as_ref() == column.as_str()))
            .unwrap_or(first),
    )
}

/// The columns a `SET` clause assigns, and the columns its expressions read.
fn set_columns(set: &str) -> (BTreeSet<ColumnName>, BTreeSet<ColumnName>) {
    let sql = format!("UPDATE probe SET {set}");
    let statements = Parser::parse_sql(&PostgreSqlDialect {}, &sql)
        .unwrap_or_else(|error| panic!("the declared change `{set}` does not parse: {error}"));
    let [Statement::Update(update)] = statements.as_slice() else {
        panic!("the declared change `{set}` is not one SET clause");
    };
    let mut assigned = BTreeSet::new();
    let mut read = BTreeSet::new();
    for assignment in &update.assignments {
        let targets = match &assignment.target {
            AssignmentTarget::ColumnName(name) => core::slice::from_ref(name),
            AssignmentTarget::Tuple(names) => names.as_slice(),
        };
        assigned.extend(
            targets
                .iter()
                .filter_map(|name| name.0.last()?.as_ident())
                .map(stored_column),
        );
        let _ = visit_expressions(&assignment.value, |expr| {
            match expr {
                Expr::Identifier(ident) => {
                    read.insert(stored_column(ident));
                }
                Expr::CompoundIdentifier(parts) => read.extend(parts.last().map(stored_column)),
                _ => {}
            }
            ControlFlow::<()>::Continue(())
        });
    }
    (assigned, read)
}

/// The name `PostgreSQL` stores for `ident`, folded unless quoted.
fn stored_column(ident: &Ident) -> ColumnName {
    ColumnName::from_stored(if ident.quote_style.is_some() {
        ident.value.clone()
    } else {
        ident.value.to_lowercase()
    })
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

/// One `PostgreSQL` and one `OpenFGA` container, shared by every case of one test.
///
/// Starting a pair per case cost twenty-two pairs and loaded the daemon enough to fail
/// startups. Cases run one at a time against this pair instead: each gets its own database,
/// and the roles it created are dropped after it, because a role is cluster-wide and the
/// next case spells the same names.
pub(crate) struct Cluster {
    _postgres: ContainerAsync<GenericImage>,
    _openfga: ContainerAsync<GenericImage>,
    pg_port: u16,
    grpc_port: u16,
}

impl Cluster {
    /// Start the pair, on `PostgreSQL` 18.
    pub(crate) async fn start() -> Self {
        let postgres = super::containers::start_postgres().await;
        let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
        let openfga = super::containers::start_openfga().await;
        let grpc_port = openfga.get_host_port_ipv4(8081).await.unwrap();
        Self {
            _postgres: postgres,
            _openfga: openfga,
            pg_port,
            grpc_port,
        }
    }

    /// The gRPC endpoint of the cluster's `OpenFGA`.
    pub(crate) fn openfga_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.grpc_port)
    }

    /// The URL of `database` on the cluster's `PostgreSQL`, as the superuser.
    pub(crate) fn url(&self, database: &str) -> String {
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

/// The database name a case runs in, unique within the process.
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

/// Apply the case and compare every pair, failing unless every clause side was decided.
pub(crate) async fn run_with(
    cluster: &Cluster,
    case: &ParityCase,
    expectation: Class,
    doctor: impl FnOnce(Vec<ActionRelations>) -> Vec<ActionRelations>,
) -> Run {
    let run = run_unjudged(cluster, case, &BTreeSet::new(), expectation, doctor).await;
    run.coverage.assert_complete(&case.name);
    run
}

/// Apply the case and compare every pair, leaving its clause coverage to the caller.
///
/// `decided` holds the clause sides earlier variants of the same schema decided.
async fn run_unjudged(
    cluster: &Cluster,
    case: &ParityCase,
    decided: &BTreeSet<String>,
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
    let outcome = run_in(
        &mut conn,
        cluster,
        &database,
        case,
        decided,
        expectation,
        doctor,
    )
    .await;
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
    decided: &BTreeSet<String>,
    expectation: Class,
    doctor: impl FnOnce(Vec<ActionRelations>) -> Vec<ActionRelations>,
) -> Run {
    apply_case(conn, case);
    let (planned, disclosed, deployment) = plan_case(case, expectation);
    let sources = DeclaredSources::of(&deployment);

    let answers = doctor(planned.translation().action_relations().to_vec());
    let naming = planned.translation().row_naming().to_vec();
    let inserting = resolved_declarations(case, &case.inserting, &naming);
    let update_sets = resolved_declarations(case, &case.update_sets, &naming);
    let objects = objects(
        conn,
        &naming,
        &case.not_read_directly,
        &inserting,
        &update_sets,
    );
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
    let settings = settings_maps(conn, case, planned.translation(), &sources);
    let model = Model {
        client: &client,
        answers: &answers,
        translation: planned.translation(),
        case,
        settings: &settings,
    };
    let mut observations = compare_every_pair(cluster, database, &model, &objects, &clock).await;
    assert_recipes_agree(case, &observations);
    let coverage = clause_coverage(cluster, database, case, &objects, &observations, decided);
    observations
        .extend(compare_at_future_instant(conn, case, &model, &objects, &observations).await);
    Run {
        observations,
        disclosures: disclosed,
        coverage,
    }
}

/// Fail where a row recipe answered a pair other than the model it was derived from.
///
/// A consumer answering from the changed row skips the model, so a recipe the model
/// disagrees with answers the pair as neither the model nor the database does.
fn assert_recipes_agree(case: &ParityCase, observations: &[Mismatch]) {
    let disagreements: Vec<String> = observations
        .iter()
        .filter(|observation| {
            observation
                .local
                .is_some_and(|local| local != observation.openfga)
        })
        .map(ToString::to_string)
        .collect();
    assert!(
        disagreements.is_empty(),
        "{}: the row recipes and the model disagree:\n{}",
        case.name,
        disagreements.join("\n")
    );
}

/// Put the case's schema and rows in the database it was given.
fn apply_case(conn: &mut PgConnection, case: &ParityCase) {
    for sql in &case.prelude {
        conn.batch_execute(sql)
            .unwrap_or_else(|error| panic!("{}: prelude {sql}: {error}", case.name));
    }
    if let Some(zone) = &case.session_time_zone {
        conn.batch_execute(&format!("SET TIME ZONE '{zone}'"))
            .unwrap_or_else(|error| panic!("{}: setting the zone {zone}: {error}", case.name));
    }
    if let Some(locale) = &case.monetary_locale {
        conn.batch_execute(&format!("SET lc_monetary = '{locale}'"))
            .unwrap_or_else(|error| panic!("{}: setting lc_monetary {locale}: {error}", case.name));
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
) -> (
    rls2fga::translator::Outputs,
    Vec<Disclosure>,
    rls2fga::parser::sql_parser::Deployment,
) {
    // The roles a case runs its callers as are created by its prelude and seed, and the
    // deployment resolves them in the schema it reads, so all three are read together.
    let mut source = format!(
        "CREATE ROLE {} LOGIN NOINHERIT;\n",
        super::deployment::LOGIN_ROLE
    );
    for sql in case.prelude.iter().chain([&case.schema]).chain(&case.seed) {
        if !is_do_block(sql) {
            source.push_str(sql.trim().trim_end_matches(';'));
            source.push_str(";\n");
        }
    }
    let db = match &case.session_time_zone {
        Some(zone) => rls2fga::parser::sql_parser::parse_schema_in_time_zone(&source, zone),
        None => rls2fga::parser::sql_parser::parse_schema(&source),
    }
    .expect("schema should parse");
    let deployment = super::deployment::caller_deployment_acting_as(
        &case.acting_roles(),
        case.settings.iter().cloned(),
    );
    let (classified, db, registry) = super::classify_db_confirming(
        db,
        case.registry_json.as_deref(),
        case.monetary_locale.as_deref(),
        &case.attribute_columns,
        &deployment,
    );
    let planned = super::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let disclosed: Vec<Disclosure> = planned
        .notes()
        .iter()
        .filter(|note| note.severity().diverges_from_database())
        .map(licence_of)
        .collect();
    hold_to_class(case, expectation, &disclosed);
    (planned, disclosed, deployment)
}

/// Whether `sql` is one anonymous `DO` block, which sets up the database and declares no
/// object the translation reads.
fn is_do_block(sql: &str) -> bool {
    matches!(
        Parser::parse_sql(&PostgreSqlDialect {}, sql).as_deref(),
        Ok([Statement::Do(_)])
    )
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

    let writes: Vec<_> = tuples
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
    instant: &Instant,
) -> Vec<Mismatch> {
    let case = model.case;
    let mut observations = Vec::new();
    for principal in &case.principals {
        let mut owned = caller_connection(cluster, database, case);
        let conn = &mut owned;
        let clock = clock_context(conn, model, instant);
        let mut raised = false;
        for object in objects {
            for statement in COMPARED {
                let Some(answer) =
                    postgres_allows(conn, case, principal, object, statement, &mut raised)
                else {
                    continue;
                };
                let context = asked_context(principal, &clock, &model.settings[&principal.subject]);
                let produced = answer.produced.as_ref();
                let local = local_allows(model, principal, &context, object, statement, produced);
                let openfga =
                    openfga_allows(model, principal, &context, object, statement, produced).await;
                observations.push(Mismatch {
                    subject: principal.subject.clone(),
                    object: object.name.clone(),
                    table: object.table.clone(),
                    statement,
                    postgres: answer.postgres,
                    openfga,
                    local,
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
        assert!(
            !principal.reads_a_non_json_document || raised,
            "{}: {} claims to parse a document that is not `JSON`, and no read of any row \
             raised, so the claim is stale",
            case.name,
            principal.subject
        );
    }
    observations
}

/// A connection of one caller's own, in the zone a login runs in.
///
/// A caller that set nothing is a real state and a shared connection cannot spell it.
/// Setting a custom key defines it for the whole session, so after one caller sets
/// `app.who` the next reads it back as the empty string rather than finding it unset, and
/// the answers would depend on the order the callers were declared in.
fn caller_connection(cluster: &Cluster, database: &str, case: &ParityCase) -> PgConnection {
    let mut conn = super::containers::connect_postgres_with_retry(&cluster.url(database));
    // Diesel sets `UTC` on connect, where a login runs in its database's zone.
    conn.batch_execute("RESET TimeZone")
        .unwrap_or_else(|error| panic!("{}: resetting the zone: {error}", case.name));
    conn
}

/// One policy as the catalog holds it.
#[derive(QueryableByName)]
struct PolicyRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    namespace: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    relation: String,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    relation_oid: i64,
    #[diesel(sql_type = diesel::sql_types::Text)]
    policy: String,
    /// `polcmd`, `*` for `ALL`, `r`, `a`, `w` or `d`.
    #[diesel(sql_type = diesel::sql_types::Text)]
    command: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    using_clause: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    check_clause: Option<String>,
}

#[derive(QueryableByName)]
struct RelationOid {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    oid: i64,
}

/// One `USING` or `WITH CHECK` clause of one policy, and the statements that fix its value.
struct Clause {
    /// The schema of the table the policy is on.
    namespace: String,
    /// The table the policy is on.
    relation: String,
    /// The `oid` of that table.
    relation_oid: i64,
    /// The policy's name.
    policy: String,
    /// Which of the policy's clauses this is.
    kind: ClauseKind,
    /// The `ALTER POLICY` setting the clause to `true`, which shows every answer its being
    /// false decided. [`None`] where the clause is the literal `true` and denies nothing.
    held: Option<String>,
    /// The `ALTER POLICY` setting the clause to `false`, which shows every answer its being
    /// true decided. [`None`] where the clause is the literal `false` and grants nothing.
    refused: Option<String>,
}

impl Clause {
    /// How a failure names one side of it.
    fn label(&self, side: Side) -> String {
        format!(
            "policy {} on {}.{}, {}, {}",
            self.policy, self.namespace, self.relation, self.kind, side
        )
    }

    /// Whether `waiver` names this clause's `side`.
    fn waived_by(&self, waiver: &Unobservable, side: Side) -> bool {
        waiver.policy == self.policy
            && waiver.clause == self.kind
            && waiver.side == side
            && (waiver.table == self.relation
                || waiver.table == format!("{}.{}", self.namespace, self.relation))
    }
}

/// Every clause of every policy in the case's database.
///
/// A policy for `ALL` or `UPDATE` without `WITH CHECK` checks the new row with its `USING`
/// expression, so that clause is two, fixed apart. The expressions are re-applied as the
/// catalog deparses them, in the session that deparsed them.
fn clauses(conn: &mut PgConnection, case: &ParityCase) -> Vec<Clause> {
    let policies: Vec<PolicyRow> = diesel::sql_query(
        "SELECT n.nspname::text AS namespace, c.relname::text AS relation,
                c.oid::bigint AS relation_oid, p.polname::text AS policy,
                p.polcmd::text AS command,
                pg_get_expr(p.polqual, p.polrelid) AS using_clause,
                pg_get_expr(p.polwithcheck, p.polrelid) AS check_clause
         FROM pg_policy p
         JOIN pg_class c ON c.oid = p.polrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
         ORDER BY n.nspname, c.relname, p.polname",
    )
    .load(conn)
    .unwrap_or_else(|error| panic!("{}: reading the policies: {error}", case.name));
    let mut clauses = Vec::new();
    for row in policies {
        let quoted = |name: &str| format!("\"{}\"", name.replace('"', "\"\""));
        let target = format!(
            "{} ON {}.{}",
            quoted(&row.policy),
            quoted(&row.namespace),
            quoted(&row.relation)
        );
        let clause =
            |kind: ClauseKind, expression: &str, ablation: &dyn Fn(&str) -> String| Clause {
                namespace: row.namespace.clone(),
                relation: row.relation.clone(),
                relation_oid: row.relation_oid,
                policy: row.policy.clone(),
                kind,
                held: (!expression.eq_ignore_ascii_case("true")).then(|| ablation("true")),
                refused: (!expression.eq_ignore_ascii_case("false")).then(|| ablation("false")),
            };
        let checks_with_using =
            row.check_clause.is_none() && matches!(row.command.as_str(), "*" | "w");
        if let Some(using) = &row.using_clause {
            clauses.push(clause(ClauseKind::Using, using, &|value| {
                if checks_with_using {
                    format!("ALTER POLICY {target} USING ({value}) WITH CHECK ({using})")
                } else {
                    format!("ALTER POLICY {target} USING ({value})")
                }
            }));
            if checks_with_using {
                clauses.push(clause(ClauseKind::UsingAsCheck, using, &|value| {
                    format!("ALTER POLICY {target} WITH CHECK ({value})")
                }));
            }
        }
        if let Some(check) = &row.check_clause {
            clauses.push(clause(ClauseKind::Check, check, &|value| {
                format!("ALTER POLICY {target} WITH CHECK ({value})")
            }));
        }
    }
    clauses
}

/// The sides of the case's policy clauses it left undecided, a side being decided where it
/// grants or denies some compared answer on its table.
///
/// A clause's translation can be wrong two ways. The model granting where the clause is
/// false shows only on a pair the clause's being false denied, and the model denying where
/// it is true only on a pair its being true granted, so the seed has to hold both. Each is
/// found by fixing the clause to the other value, alone, inside a transaction the probes
/// run in and that is rolled back, and asking only the database again. Counting per table
/// and statement would miss a clause another permissive one shadows.
///
/// A side in `decided`, which an earlier variant of the same schema already decided, counts
/// as decided without being fixed again, so variants together reach the verdict each would
/// reach alone.
fn clause_coverage(
    cluster: &Cluster,
    database: &str,
    case: &ParityCase,
    objects: &[Object],
    observations: &[Mismatch],
    decided: &BTreeSet<String>,
) -> Coverage {
    let mut owner = caller_connection(cluster, database, case);
    let clauses = clauses(&mut owner, case);
    let mut relation_oids: BTreeMap<&str, i64> = BTreeMap::new();
    for object in objects {
        if !relation_oids.contains_key(object.table.as_str()) {
            let RelationOid { oid } = diesel::sql_query(format!(
                "SELECT '{}'::regclass::oid::bigint AS oid",
                object.table
            ))
            .get_result(&mut owner)
            .unwrap_or_else(|error| panic!("{}: resolving {}: {error}", case.name, object.table));
            relation_oids.insert(&object.table, oid);
        }
    }
    let mut connections: Vec<PgConnection> = case
        .principals
        .iter()
        .map(|_| caller_connection(cluster, database, case))
        .collect();
    let mut coverage = Coverage::default();
    let mut matched = vec![false; case.unobservable.len()];
    for clause in &clauses {
        let on_table: Vec<&Object> = objects
            .iter()
            .filter(|object| relation_oids[object.table.as_str()] == clause.relation_oid)
            .collect();
        let mut changes_an_answer = |ablation: &str| {
            case.principals
                .iter()
                .zip(&mut connections)
                .any(|(principal, conn)| {
                    ablation_changes_an_answer(
                        conn,
                        case,
                        principal,
                        ablation,
                        &on_table,
                        observations,
                    )
                })
        };
        for (side, ablation) in [
            (Side::Denies, clause.held.as_deref()),
            (Side::Grants, clause.refused.as_deref()),
        ] {
            let Some(ablation) = ablation else {
                continue;
            };
            let waiver = case
                .unobservable
                .iter()
                .position(|waiver| clause.waived_by(waiver, side));
            if let Some(at) = waiver {
                matched[at] = true;
            }
            let label = clause.label(side);
            let changed = decided.contains(&label) || changes_an_answer(ablation);
            match (changed, waiver) {
                (false, None) => {
                    coverage.untested.insert(label);
                }
                (true, Some(at)) => {
                    coverage.stale.insert(format!(
                        "{label}, waived as \"{}\"",
                        case.unobservable[at].reason
                    ));
                    coverage.decided.insert(label);
                }
                (true, None) => {
                    coverage.decided.insert(label);
                }
                (false, Some(_)) => {}
            }
        }
    }
    coverage.unmatched = case
        .unobservable
        .iter()
        .zip(matched)
        .filter(|(_, matched)| !matched)
        .map(|(waiver, _)| {
            format!(
                "{}.{}, {}, {}",
                waiver.table, waiver.policy, waiver.clause, waiver.side
            )
        })
        .collect();
    coverage
}

/// The clause sides a case, or a set of variants of one schema, left undecided.
#[derive(Debug, Default)]
pub(crate) struct Coverage {
    /// Sides whose fixing changed no compared answer, and no waiver names.
    untested: BTreeSet<String>,
    /// Waived sides whose fixing changed a compared answer, each with its reason.
    stale: BTreeSet<String>,
    /// Waivers naming no clause side.
    unmatched: BTreeSet<String>,
    /// Sides whose fixing changed a compared answer, waived or not.
    decided: BTreeSet<String>,
}

impl Coverage {
    /// The coverage of variants of one schema taken together. A side is untested only where
    /// every variant left it so, a waiver is wrong where any variant decides its side, and a
    /// waiver names nothing only where it names nothing in every variant.
    fn together<'run>(mut runs: impl Iterator<Item = &'run Coverage>) -> Self {
        let Some(first) = runs.next() else {
            return Self::default();
        };
        let mut together = Self {
            untested: first.untested.clone(),
            stale: first.stale.clone(),
            unmatched: first.unmatched.clone(),
            decided: first.decided.clone(),
        };
        for coverage in runs {
            together
                .untested
                .retain(|side| coverage.untested.contains(side));
            together.stale.extend(coverage.stale.iter().cloned());
            together
                .unmatched
                .retain(|waiver| coverage.unmatched.contains(waiver));
            together.decided.extend(coverage.decided.iter().cloned());
        }
        together
    }

    /// Fail unless every side was decided or rightly waived.
    fn assert_complete(&self, name: &str) {
        let list = |sides: &BTreeSet<String>| {
            sides
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join("\n  ")
        };
        assert!(
            self.untested.is_empty(),
            "{name}: fixing each of these clauses to the other value changed no compared \
             answer on its table, so the seed never tests that side of it\n  {}",
            list(&self.untested)
        );
        assert!(
            self.stale.is_empty(),
            "{name}: these sides are declared unobservable, and fixing the clause changed a \
             compared answer, so the waiver is wrong\n  {}",
            list(&self.stale)
        );
        assert!(
            self.unmatched.is_empty(),
            "{name}: these waivers name no clause side the case has\n  {}",
            list(&self.unmatched)
        );
    }
}

/// Whether some compared pair of `principal` on `on_table` gets another answer from the
/// database while `ablation` holds.
fn ablation_changes_an_answer(
    conn: &mut PgConnection,
    case: &ParityCase,
    principal: &Principal,
    ablation: &str,
    on_table: &[&Object],
    observations: &[Mismatch],
) -> bool {
    let mut changed = false;
    let mut raised = false;
    let outcome = conn.transaction::<(), diesel::result::Error, _>(|conn| {
        conn.batch_execute(ablation)?;
        changed = on_table.iter().any(|object| {
            COMPARED.into_iter().any(|statement| {
                let Some(before) = observations.iter().find(|observation| {
                    observation.subject == principal.subject
                        && observation.object == object.name
                        && observation.statement == statement
                }) else {
                    return false;
                };
                postgres_allows(conn, case, principal, object, statement, &mut raised)
                    .is_some_and(|after| after.postgres != before.postgres)
            })
        });
        Err(diesel::result::Error::RollbackTransaction)
    });
    match outcome {
        Err(diesel::result::Error::RollbackTransaction) => changed,
        Err(error) => panic!("{}: {ablation}: {error}", case.name),
        Ok(()) => unreachable!("the transaction body always rolls back"),
    }
}

/// The context a check carries, with the clock parameters where the caller needs them
/// and the `settings` map beside them.
fn asked_context(
    principal: &Principal,
    clock: &serde_json::Map<String, serde_json::Value>,
    settings: &serde_json::Value,
) -> serde_json::Value {
    let mut context = principal.context.clone();
    if let Some(entries) = context.as_object_mut() {
        if principal.carries_request_time {
            entries.extend(clock.clone());
        }
        entries.insert("settings".to_string(), settings.clone());
    }
    context
}

/// The `settings` map a check carries, each declared value that travels there and that the
/// caller set under its parameter name, absent where the caller set nothing so it reads as
/// `PostgreSQL`'s `NULL`.
pub(crate) fn settings_map(sources: &DeclaredSources, principal: &Principal) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for source in sources.iter().filter(|source| source.travels_in_settings()) {
        if let Some(text) = session_text(source, principal) {
            map.insert(
                source.request_parameter().to_string(),
                serde_json::Value::String(text),
            );
        }
    }
    serde_json::Value::Object(map)
}

/// The `settings` map of every principal by subject, holding beside [`settings_map`] what
/// each normalization a note asks for makes of a value the principal set, computed by the
/// database `conn` reaches, as a checker asks the database the policies run in.
fn settings_maps(
    conn: &mut PgConnection,
    case: &ParityCase,
    translation: &rls2fga::translator::Translation,
    sources: &DeclaredSources,
) -> BTreeMap<String, serde_json::Value> {
    let normalized: Vec<_> = translation
        .notes()
        .iter()
        .filter_map(|note| match note {
            TranslationNote::CallerSuppliesConditionParameter {
                parameter,
                normalization: Some(normalization),
                ..
            } => sources
                .iter()
                .filter_map(|source| sources.normalized(source, *normalization))
                .find(|normalized| normalized.request_parameter() == parameter),
            _ => None,
        })
        .collect();
    let mut maps = BTreeMap::new();
    for principal in &case.principals {
        let mut map = settings_map(sources, principal);
        for source in &normalized {
            let Some(text) = session_text(source, principal) else {
                continue;
            };
            let function = source
                .normalization()
                .expect("a normalized source")
                .function_name();
            let value: String = diesel::select(
                diesel::dsl::sql::<diesel::sql_types::Text>(&format!("{function}("))
                    .bind::<diesel::sql_types::Text, _>(&text)
                    .sql(")"),
            )
            .get_result(conn)
            .unwrap_or_else(|error| panic!("{}: {function} of {text:?}: {error}", case.name));
            map.as_object_mut()
                .expect("the settings map is an object")
                .insert(
                    source.request_parameter().to_string(),
                    serde_json::Value::String(value),
                );
        }
        assert!(
            maps.insert(principal.subject.clone(), map).is_none(),
            "{}: two principals share the subject {}",
            case.name,
            principal.subject
        );
    }
    maps
}

/// The text `principal` set for `source`, the whole setting or the field the source
/// takes out of it, absent where it set none.
fn session_text(source: &DeclaredSource, principal: &Principal) -> Option<String> {
    let value = principal
        .session
        .iter()
        .find(|(name, _)| name.trim().to_ascii_lowercase() == source.setting_key())
        .map(|(_, value)| value.as_str())?;
    if source.path().is_empty() {
        Some(value.to_string())
    } else {
        jsonb_text(value, source.path())
    }
}

/// `document` read at `path` rendered as `->>` would, so the map holds the same text
/// `PostgreSQL` compares, and `null` leaves the key absent.
fn jsonb_text(document: &str, path: &[String]) -> Option<String> {
    let document = serde_json::from_str::<serde_json::Value>(document).ok()?;
    let mut node = &document;
    for segment in path {
        node = node.get(segment)?;
    }
    match node {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Null => None,
        other => Some(other.to_string()),
    }
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

/// Run each of `variants`, states of one schema, under `deadline` each, failing unless
/// every clause side was decided by one of them or rightly waived.
///
/// A state that exists to reach a few arms, such as an organization between its creation
/// and its first admin, decides only those, and the other variants decide the rest.
pub(crate) async fn run_variants_before(
    cluster: &Cluster,
    variants: &[ParityCase],
    deadline: Duration,
) -> Vec<Run> {
    let mut runs: Vec<Run> = Vec::with_capacity(variants.len());
    let mut decided = BTreeSet::new();
    for case in variants {
        let run = tokio::time::timeout(
            deadline,
            run_unjudged(cluster, case, &decided, Class::Exact, |answers| answers),
        )
        .await
        .unwrap_or_else(|_| panic!("{} exceeded its parity deadline", case.name));
        decided.extend(run.coverage.decided.iter().cloned());
        runs.push(run);
    }
    let names: Vec<&str> = variants.iter().map(|case| case.name.as_str()).collect();
    Coverage::together(runs.iter().map(|run| &run.coverage)).assert_complete(&names.join(", "));
    runs
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

    let clock = clock_context(conn, model, &instant);
    let mut observations = Vec::new();
    for principal in &case.principals {
        for object in objects {
            let postgres = visible
                .iter()
                .any(|pair| pair.subject == principal.subject && pair.object == object.name);
            let mut context = principal.context.clone();
            if let Some(entries) = context.as_object_mut() {
                entries.extend(clock.clone());
                entries.insert(
                    "settings".to_string(),
                    model.settings[&principal.subject].clone(),
                );
            }
            let openfga = openfga_allows(
                model,
                principal,
                &context,
                object,
                ActionStatement::Select,
                None,
            )
            .await;
            observations.push(Mismatch {
                subject: principal.subject.clone(),
                object: object.name.clone(),
                table: object.table.clone(),
                statement: ActionStatement::Select,
                postgres,
                openfga,
                local: None,
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
    let mut loaded = BTreeSet::new();
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
                records_from_row(description, &json_row::JsonRow(row)).unwrap_or_else(|error| {
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
/// its key replaced, which keeps every column a policy reads. A keyless table's probe is
/// the existing row itself. The statement is always rolled back, so nothing the runner
/// compares afterwards sees the probe.
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
) -> Option<ProbeResult> {
    let Attempt {
        case,
        object,
        statement,
        ..
    } = *attempt;
    let table = &object.table;
    let row = object
        .row
        .as_object()
        .expect("`to_jsonb` of a row is an object");
    let keys = &object.keys;
    // An upsert without a key has no arbiter to conflict on, so it cannot be written.
    if keys.is_empty() && statement == ActionStatement::InsertOnConflictUpdate {
        return None;
    }
    let arbiter = keys
        .iter()
        .map(|key| format!("\"{key}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let listed = listed_columns(object, statement);
    let list = listed
        .iter()
        .map(|column| format!("\"{column}\""))
        .collect::<Vec<_>>()
        .join(", ");

    // A keyless table's probe and an upsert copy the seed row, and an insert onto a fresh
    // key copies it with the key replaced.
    let payload = if keys.is_empty() || statement == ActionStatement::InsertOnConflictUpdate {
        assert!(
            !keys.is_empty() || object.inserting.is_none(),
            "{}: {table} has no key for a declared insert to replace",
            case.name
        );
        object.row.clone()
    } else {
        let declared: &[(String, String)] = object
            .inserting
            .as_ref()
            .map_or(&[], |inserting| &inserting.values);
        let mut probe = row.clone();
        // One fresh column makes the whole key fresh, and the others keep the values a
        // policy may read. A key column the statement leaves out is the database's to
        // assign, so it is fresh already. A case declaring a key column chooses the key
        // itself, and a seeded row on the same key raises a unique violation, which fails
        // the case.
        let chooses_key = declared.iter().any(|(column, _)| keys.contains(column));
        let mintable: Vec<&String> = keys.iter().filter(|key| listed.contains(key)).collect();
        if !chooses_key && !mintable.is_empty() {
            let (key, fresh) = mintable
                .iter()
                .find_map(|key| {
                    let current = row.get(*key).expect("a key column is a column of its row");
                    fresh_key(conn, case, table, key, current).map(|fresh| (*key, fresh))
                })
                .unwrap_or_else(|| {
                    panic!(
                        "{}: no key column of {table} has a type the runner mints a fresh \
                         value for, so its inserts would go uncompared",
                        case.name
                    )
                });
            probe.insert(key.clone(), fresh);
        }
        for (column, value) in declared {
            probe.insert(column.clone(), serde_json::Value::String(value.clone()));
        }
        serde_json::Value::Object(probe)
    };
    // A column the statement leaves out takes a default, an identity or a generated value,
    // which only the database computes, so the owner writes the same row first and the
    // runner asks about the row it read back.
    let rehearsed = row.keys().any(|column| !listed.contains(column));
    if rehearsed {
        assert_no_role_default(conn, case, table, listed);
    }
    let written = Written {
        payload: payload.to_string(),
        produced: (!rehearsed).then_some(payload),
    };
    let source = format!(
        "INSERT INTO {table} AS written ({list}) SELECT {list} \
         FROM jsonb_populate_record(NULL::{table}, $1::jsonb)"
    );
    if keys.is_empty() && statement == ActionStatement::InsertReturning {
        // An empty row has no column to return, so the readback cannot be written.
        let returned = assignable_column(&object.non_generated, keys)?;
        let sql =
            format!("WITH inserted AS ({source} RETURNING \"{returned}\") SELECT 1 FROM inserted");
        let (postgres, produced) = attempt_write(conn, attempt, &sql, &source, &written, raised);
        return Some(ProbeResult { postgres, produced });
    }
    let spellings = match statement {
        ActionStatement::Insert => {
            let alternative = format!("{source} ON CONFLICT DO NOTHING");
            [source.clone(), alternative]
        }
        ActionStatement::InsertReturning => [
            format!("WITH inserted AS ({source} RETURNING {arbiter}) SELECT 1 FROM inserted"),
            format!("{source} ON CONFLICT ({arbiter}) DO NOTHING"),
        ],
        ActionStatement::InsertOnConflictUpdate => {
            let settable = assignable_column(&object.non_generated, keys)?;
            let update = format!(
                "{source} ON CONFLICT ({arbiter}) DO UPDATE SET \"{settable}\" = excluded.\"{settable}\""
            );
            let (postgres, produced) =
                attempt_write(conn, attempt, &update, &update, &written, raised);
            return Some(ProbeResult { postgres, produced });
        }
        _ => unreachable!("{statement:?} is not a write probe"),
    };

    let answers: Vec<(bool, Option<serde_json::Value>)> = spellings
        .iter()
        .map(|sql| attempt_write(conn, attempt, sql, &source, &written, raised))
        .collect();
    assert_eq!(
        answers[0].0, answers[1].0,
        "{}: two spellings of {statement:?} on {} answered differently, so one relation \
         cannot cover both",
        case.name, object.name
    );
    let [(postgres, produced), _] = <[_; 2]>::try_from(answers).expect("two spellings");
    Some(ProbeResult { postgres, produced })
}

/// The row a write probe sends, and the row it produces where the probe alone knows it.
struct Written {
    /// The row as `JSON`, bound to every spelling.
    payload: String,
    /// The row the write produces, [`None`] where the statement leaves a column to the
    /// database, so the owner writes the row first in the caller's transaction.
    produced: Option<serde_json::Value>,
}

/// Refuse a probe leaving out a column whose default reads the role writing the row, since
/// the owner's rehearsal writes as another role and would read back another row.
fn assert_no_role_default(
    conn: &mut PgConnection,
    case: &ParityCase,
    table: &str,
    listed: &[String],
) {
    // A generated column is immutable, so only a default can read the role, and a quoted
    // literal spelling `user` is no call.
    let reading_the_role: Vec<String> = diesel::sql_query(format!(
        "SELECT a.attname AS name FROM pg_attrdef d
         JOIN pg_attribute a ON a.attrelid = d.adrelid AND a.attnum = d.adnum
         WHERE d.adrelid = '{table}'::regclass AND a.attgenerated = ''
           AND regexp_replace(pg_get_expr(d.adbin, d.adrelid), '''(?:[^'']|'''')*''', '', 'g')
               ~* '\\m(current_user|session_user|current_role|user)\\M'"
    ))
    .load::<Column>(conn)
    .unwrap_or_else(|error| panic!("{}: reading the defaults of {table}: {error}", case.name))
    .into_iter()
    .map(|Column { name }| name)
    .filter(|name| !listed.contains(name))
    .collect();
    assert!(
        reading_the_role.is_empty(),
        "{}: {table} defaults {} to the role writing the row, which a rehearsal as the owner \
         cannot reproduce",
        case.name,
        reading_the_role.join(", ")
    );
}

/// The row `statement` writes from `payload`, written in a savepoint of the caller's
/// transaction as the connection's own role, which no policy filters, and rolled back.
///
/// The caller's session values and clock hold inside it. Every sequence is put back after,
/// so the caller's statement draws the values the rehearsal drew. [`None`] where the table's
/// own integrity refuses the row.
fn rehearse_as_owner(
    conn: &mut PgConnection,
    case: &ParityCase,
    table: &str,
    statement: &str,
    payload: &str,
) -> Option<serde_json::Value> {
    let mut produced = None;
    let outcome = conn.transaction::<(), diesel::result::Error, _>(|conn| {
        conn.batch_execute("RESET ROLE")?;
        let restores: Vec<Restore> = diesel::sql_query(
            "SELECT format('SELECT setval(%L, %s, %L)', format('%I.%I', schemaname, sequencename),
                           coalesce(last_value, start_value), last_value IS NOT NULL) AS statement
             FROM pg_sequences",
        )
        .load(conn)?;
        let written =
            conn.transaction::<Option<serde_json::Value>, diesel::result::Error, _>(|conn| {
                let rows: Vec<JsonRow> =
                    diesel::sql_query(format!("{statement} RETURNING to_jsonb(written) AS row"))
                        .bind::<diesel::sql_types::Text, _>(payload)
                        .load(conn)?;
                produced = rows.into_iter().next().map(|JsonRow { row }| row);
                Err(diesel::result::Error::RollbackTransaction)
            });
        for Restore { statement } in restores {
            diesel::sql_query(statement).execute(conn)?;
        }
        match written {
            Err(diesel::result::Error::RollbackTransaction) => {}
            Err(error) if is_constraint_violation(&error) => produced = None,
            Err(error) => panic!(
                "{}: rehearsing a write on {table} as its owner: {error}",
                case.name
            ),
            Ok(_) => unreachable!("the rehearsal always rolls back"),
        }
        Err(diesel::result::Error::RollbackTransaction)
    });
    match outcome {
        Err(diesel::result::Error::RollbackTransaction) => produced,
        Err(error) => panic!(
            "{}: rehearsing a write on {table} as its owner: {error}",
            case.name
        ),
        Ok(()) => unreachable!("the transaction body always rolls back"),
    }
}

/// A statement putting one sequence back where it stood.
#[derive(QueryableByName)]
struct Restore {
    #[diesel(sql_type = diesel::sql_types::Text)]
    statement: String,
}

/// Run one write spelling as the caller and roll it back, reading a refusal as a denial,
/// with the row it produces.
///
/// Where the probe does not know that row, `rehearsal` writes it as the owner first, inside
/// the same transaction.
fn attempt_write(
    conn: &mut PgConnection,
    attempt: &Attempt,
    sql: &str,
    rehearsal: &str,
    written: &Written,
    raised: &mut bool,
) -> (bool, Option<serde_json::Value>) {
    let Attempt {
        case,
        principal,
        object,
        statement,
    } = *attempt;
    let mut produced = written.produced.clone();
    let outcome = conn.transaction::<(), diesel::result::Error, _>(|conn| {
        become_principal(conn, principal)?;
        if written.produced.is_none() {
            produced = rehearse_as_owner(conn, case, &object.table, rehearsal, &written.payload);
        }
        diesel::sql_query(sql)
            .bind::<diesel::sql_types::Text, _>(&written.payload)
            .execute(conn)?;
        // The probe is never kept, so the comparison that follows sees the seeded rows.
        Err(diesel::result::Error::RollbackTransaction)
    });
    let allowed = match outcome {
        Err(diesel::result::Error::RollbackTransaction) => true,
        // A caller that set nothing the policy reads raises rather than being filtered,
        // exactly as a read does, and the write does not happen either way.
        Err(error) if principal.reads_an_unset_setting && reads_an_unset_setting(&error) => {
            *raised = true;
            false
        }
        Err(error) if reads_as_a_policy_refusal(&error) => false,
        // A caller without the table's privilege raises `42501`, which is a denial.
        Err(error) if lacks_a_table_privilege(&error) => false,
        // A write the policy admits meets the table's own declared integrity when the
        // copy itself breaks one, and the probe reads that as allowed.
        Err(error) if is_constraint_violation(&error) => {
            if declared_constraint_block(conn, &error, &object.table, statement) {
                true
            } else {
                panic!(
                    "{}: {statement:?} on {} raised a constraint error the table does not \
                     declare: {error}",
                    case.name, object.name
                )
            }
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
    };
    (allowed, produced)
}

/// A value no row of `table` carries in `column`, in the column's own type, and for text
/// of the seed's own length, so a name spelled from it fits wherever the seed's does.
/// [`None`] for a type the runner mints nothing for.
///
/// The type has to be asked for rather than guessed from the JSON, which spells a `uuid`
/// and a `text` the same way and would hand `uuid` a value it refuses. Text keeps all but
/// its last character, so a policy reading a key's prefix reads the seed's.
fn fresh_key(
    conn: &mut PgConnection,
    case: &ParityCase,
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
    .unwrap_or_else(|error| panic!("{}: the type of {table}.{column}: {error}", case.name));
    // `character varying(20)` is a `character varying`.
    let base = kind.instant.split('(').next().unwrap_or_default();
    let replacing_last = |text: &str, alphabet: &str| -> Vec<serde_json::Value> {
        let kept = text.char_indices().last().map_or(0, |(at, _)| at);
        alphabet
            .chars()
            .map(|last| serde_json::Value::String(format!("{}{last}", &text[..kept])))
            .collect()
    };
    let candidates = match (base, current) {
        ("uuid", serde_json::Value::String(text)) => {
            let rest: String = text.chars().skip(1).collect();
            "0123456789abcdef"
                .chars()
                .map(|first| serde_json::Value::String(format!("{first}{rest}")))
                .collect()
        }
        ("text" | "character varying" | "character" | "name", serde_json::Value::String(text))
            if !text.is_empty() =>
        {
            replacing_last(text, "0123456789abcdefghijklmnopqrstuvwxyz")
        }
        ("integer" | "bigint" | "smallint", serde_json::Value::Number(number))
            if number.as_i64().is_some() =>
        {
            let start = number.as_i64().unwrap_or_default();
            (1..=16)
                .map(|step| serde_json::Value::from(start.wrapping_add(step)))
                .collect()
        }
        _ => return None,
    };
    let fresh = candidates.into_iter().find(|candidate| {
        let taken: Counted = diesel::sql_query(format!(
            "SELECT count(*) AS rows FROM {table} WHERE to_jsonb(\"{column}\") = $1::jsonb"
        ))
        .bind::<diesel::sql_types::Text, _>(candidate.to_string())
        .get_result(conn)
        .unwrap_or_else(|error| panic!("{}: reading {table}.{column}: {error}", case.name));
        taken.rows == 0
    });
    Some(fresh.unwrap_or_else(|| {
        panic!(
            "{}: every fresh value the runner tried for {table}.{column} is taken",
            case.name
        )
    }))
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

/// The case's declarations per table, keyed the way an object names its table.
///
/// A case spells a table the way its schema does, `notes`, while an object carries
/// `TableId::sql_name`, `"public"."notes"`. Comparing those as text finds nothing, so the
/// spelling is resolved through the identities the model already named. A declaration
/// matching no table is a typo in the case, and silently disabling it would look like the
/// write simply not being compared.
fn resolved_declarations<'case, T>(
    case: &'case ParityCase,
    declared: &'case BTreeMap<String, T>,
    naming: &[RowNaming],
) -> BTreeMap<String, &'case T> {
    let mut resolved = BTreeMap::new();
    for (spelling, declaration) in declared {
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
            resolved
                .insert(entry.table.sql_name(), declaration)
                .is_none(),
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
        // Four that narrow and name their table: the parent reads its own rows only, so
        // its children's fall closed on that type, an expression nobody classified denies
        // what the database may grant, and a written row's unreadable fact denies its write.
        TranslationNote::InheritanceParentReadsOwnRowsOnly { table, .. }
        | TranslationNote::BridgeColumnMissing { table, .. }
        | TranslationNote::RowsCannotBeNamed { table, .. }
        | TranslationNote::ResultingRowFactUnreadable { table, .. } => Licence::Located {
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
