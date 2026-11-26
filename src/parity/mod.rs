//! Replaying `sql-traits`' recorded row-level security cases on the model.
//!
//! A case's `schema.sql` and `seed.sql` load into a fresh PostgreSQL database, a
//! [`Database`](crate::parity::Database), which stays the source of the model's tuples
//! and of each probe's rows. [`replay`](crate::parity::replay) translates the schema,
//! loads the model and the seeded rows' records into a store of their own on a running
//! `OpenFGA`, and answers each probe the way `sql_traits::parity::Fixture::judge`
//! compares with PostgreSQL's recorded answer.
//!
//! A statement the caller's acting role lacks a privilege for fails before any row, as
//! [`Translation::acting_privileges`](crate::translator::Translation::acting_privileges)
//! answers, a read with `PostgreSQL`'s `permission denied for table <t>` and a write with
//! SQLSTATE 42501. Otherwise a write's verdict is split the way PostgreSQL acts on a row.
//! A row whose stored row fails a judgement is denied alone, as a `USING` clause skips it.
//! A row whose stored row passes while the row it would produce, or a column relation,
//! fails aborts the whole statement, so every row of that statement is denied.
//!
//! A statement naming a view running with its owner's rights is answered by the table the
//! view writes, as [`Translation::view_paths`](crate::translator::Translation::view_paths)
//! routes it, and the owner's run producing its row writes that table, where the view's
//! check option cannot refuse the row the model judges.

mod database;
mod model;

use alloc::{
    borrow::{Cow, ToOwned},
    boxed::Box,
    collections::{btree_map::Entry, BTreeMap},
    format,
    string::{String, ToString},
    vec::Vec,
};

use diesel::result::Error as DieselError;
use openfga_client::client::OpenFgaServiceClient;
use serde_json::Value;
use sql_traits::parity::{
    identifier, Answer, Caller, Case, EngineAnswer, MissingKeyColumn, RecordedAnswer, Shape, Table,
    Write,
};
use sql_traits::prelude::Deployment;

pub use database::Database;
use model::{Model, RowProbe, Verdict};

use crate::client::WriteModelError;
use crate::generator::model_generator::PlanningError;
use crate::generator::tuple_generator::TupleRowError;
use crate::parser::sql_parser::{parse_schema, SchemaError};
use crate::translator::TranslatorBuilder;
use crate::types::{
    ActionStatement, ColumnCommand, ColumnName, ConfidenceLevel, RecordError, ViewPath,
};

/// One row a caller's statement reaches, to be answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    /// The caller's name.
    pub caller: String,
    /// The row, its table name and key joined by a colon.
    pub row: String,
    /// The statement the caller runs, spelled as the case's tables spell it.
    pub statement: String,
}

impl From<&RecordedAnswer> for Probe {
    fn from(recorded: &RecordedAnswer) -> Self {
        Self {
            caller: recorded.caller.clone(),
            row: recorded.row.clone(),
            statement: recorded.statement.clone(),
        }
    }
}

/// The model's run of one case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Replay {
    /// Why the translator refuses the schema, absent when `Translation::outputs` accepts
    /// it.
    pub refusal: Option<String>,
    /// One answer per probe, in the probes' order.
    pub answers: Vec<EngineAnswer>,
}

/// Why a case could not be replayed at all. A failure confined to one probe is that
/// probe's [`Answer::Error`] instead.
#[derive(Debug, thiserror::Error)]
pub enum ParityError {
    /// The PostgreSQL URL does not parse.
    #[error("the PostgreSQL URL is invalid")]
    Url(#[from] url::ParseError),
    /// PostgreSQL refused the connection.
    #[error("cannot connect to PostgreSQL")]
    Connect(#[from] diesel::ConnectionError),
    /// The cluster runs another major version than 18.
    #[error("PostgreSQL 18 is required, the server is version {0}")]
    Version(String),
    /// The schema does not parse far enough to name the roles it creates.
    #[error("the roles schema.sql creates cannot be read")]
    Roles(#[source] sqlparser::parser::ParserError),
    /// A role the case creates already exists in the cluster.
    #[error("the case's roles already exist in the cluster")]
    RolesExist,
    /// PostgreSQL refused `schema.sql`.
    #[error("applying schema.sql")]
    Schema(#[source] DieselError),
    /// PostgreSQL refused `seed.sql`.
    #[error("applying seed.sql")]
    Seed(#[source] DieselError),
    /// The table owner's run of a write failed.
    #[error("running `{statement}` as the table owner")]
    Resulting {
        /// The write, returning the row it produces.
        statement: String,
        /// The database's error.
        #[source]
        source: DieselError,
    },
    /// Any other query failed.
    #[error("querying the case's database")]
    Query(#[from] DieselError),
    /// A measured table holds no seeded row.
    #[error("{0} has no seeded rows")]
    NoSeededRows(String),
    /// A write targets a table the case does not declare.
    #[error("a write targets undeclared table {0}")]
    UndeclaredTable(String),
    /// A seeded or inserted row lacks a key column.
    #[error(transparent)]
    MissingKeyColumn(#[from] MissingKeyColumn),
    /// `OpenFGA` is unreachable.
    #[error("cannot connect to OpenFGA")]
    Transport(#[from] openfga_client::tonic::transport::Error),
    /// `OpenFGA` refused a store request.
    #[error("OpenFGA refused a store request")]
    Openfga(#[source] Box<openfga_client::tonic::Status>),
    /// `OpenFGA` refused the model.
    #[error("writing the model")]
    WriteModel(#[source] Box<WriteModelError>),
    /// `OpenFGA` refused the records.
    #[error("writing the records")]
    Tuples(#[source] Box<openfga_client::error::Error>),
    /// A tuple query's row lacks a text column.
    #[error("a tuple query row has no {0} column")]
    TupleColumn(&'static str),
    /// A tuple query's row is not a record of the model.
    #[error("a tuple query row is not a record")]
    TupleRow(#[from] TupleRowError),
    /// A seeded row does not render its records.
    #[error("a seeded row does not render its records")]
    Record(#[from] RecordError),
    /// A record's condition context is not a protobuf struct.
    #[error("a record's condition context")]
    Context(#[from] serde_json::Error),
}

/// Why the translator refuses a schema outright, before any gate.
#[derive(Debug, thiserror::Error)]
enum Untranslatable {
    #[error(transparent)]
    Parse(#[from] SchemaError),
    #[error(transparent)]
    Plan(#[from] PlanningError),
}

/// Why one probe has no answer from the model.
#[derive(Debug, thiserror::Error)]
enum ProbeError {
    #[error("the case has no caller {0}")]
    UnknownCaller(String),
    #[error("no statement of the case is spelled `{0}`")]
    UnknownStatement(String),
    #[error("the statement reaches no row {0}")]
    UnreachedRow(String),
    #[error("the translation has no row naming for {0}")]
    NoRowNaming(String),
    #[error("the translation reports no privileges of acting role {0} on the table")]
    NoPrivileges(String),
    #[error("the row has no OpenFGA object name")]
    Unnamed,
    #[error("the translation has no {0:?} answer")]
    NoAnswer(ActionStatement),
    #[error("the statement reaches no stored row")]
    NoStoredRow,
    #[error("the statement produces no resulting row")]
    NoResultingRow,
    #[error("the translation names no resulting row for the judgement")]
    NoResultingNaming,
    #[error("the statement touches no {0:?} columns")]
    NoColumns(ColumnCommand),
    #[error("unsupported action answer {0}")]
    Unsupported(String),
    #[error("the deployment declares no caller setting")]
    NoCallerSetting,
    #[error("caller {caller} does not set {setting}")]
    UnsetSetting { caller: String, setting: String },
    #[error("the row does not render")]
    Record(#[from] RecordError),
    #[error("the check context is not a protobuf struct")]
    Context(#[from] serde_json::Error),
    #[error("the check failed")]
    Check(#[source] Box<openfga_client::error::Error>),
}

/// Answer `probes` of `case` on the model `deployment` translates its schema into, with
/// `database` holding the case's seeded rows and `openfga_url` the gRPC endpoint of a
/// running `OpenFGA`.
///
/// Each probe's statement is matched by its exact text against the case's reads and
/// writes as `sql_traits::parity::Table` spells them, and its row by the key of a seeded
/// row, or of an insert's row. A probe naming no such caller, statement or row is answered
/// [`Answer::Error`]. A translator refusing the schema outright answers every probe
/// [`Answer::Refused`].
///
/// # Errors
///
/// Returns a [`ParityError`] when the seeded rows cannot be read or `OpenFGA` cannot load
/// the model.
pub async fn replay(
    case: &Case,
    deployment: &Deployment,
    probes: impl IntoIterator<Item = Probe>,
    database: &mut Database,
    openfga_url: &str,
) -> Result<Replay, ParityError> {
    let translation = match translate(case, deployment) {
        Ok(translation) => translation,
        Err(error) => {
            let reason = error.to_string();
            return Ok(Replay {
                answers: probes
                    .into_iter()
                    .map(|probe| probe.answered(Answer::Refused(reason.clone())))
                    .collect(),
                refusal: Some(reason),
            });
        }
    };
    let refusal = translation
        .clone()
        .outputs()
        .err()
        .map(|error| error.to_string());
    let outputs = translation.outputs_accepting_gaps();
    let mut seeded = BTreeMap::new();
    for table in &case.config.tables {
        let rows = database.rows(&identifier(&table.name))?;
        if rows.is_empty() {
            return Err(ParityError::NoSeededRows(table.name.clone()));
        }
        seeded.insert(table.name.as_str(), rows);
    }
    let statements = statements(case, &seeded, outputs.translation().view_paths(), database)?;
    let mut service = OpenFgaServiceClient::connect(openfga_url.to_owned()).await?;
    let model = Model::create(&mut service, &case.name, deployment, outputs, database).await?;
    let answers = answer(&model, case, &statements, probes).await;
    model.delete(&mut service).await?;
    Ok(Replay { refusal, answers })
}

impl Probe {
    fn answered(self, answer: Answer) -> EngineAnswer {
        EngineAnswer {
            caller: self.caller,
            row: self.row,
            statement: self.statement,
            answer,
        }
    }
}

/// Translate the schema at confidence B under `deployment`.
fn translate(
    case: &Case,
    deployment: &Deployment,
) -> Result<crate::translator::Translation, Untranslatable> {
    let parsed = parse_schema(&case.schema)?;
    Ok(TranslatorBuilder::new(deployment.clone())
        .with_min_confidence(ConfidenceLevel::B)
        .build()
        .translate(&parsed)?)
}

/// One statement a caller can run and every row it reaches.
struct Statement<'a> {
    table: &'a Table,
    action: ActionStatement,
    writes: bool,
    columns: BTreeMap<ColumnCommand, Vec<ColumnName>>,
    rows: Vec<TargetRow<'a>>,
}

/// One row a statement reaches.
struct TargetRow<'a> {
    /// The row, its table name and key joined by a colon.
    row: String,
    /// The seeded row the statement reaches, absent for an insert.
    existing: Option<&'a Value>,
    /// The row the table owner's run of the statement produces, absent for a read or a
    /// delete.
    resulting: Option<Value>,
}

/// Every read and write the case measures, keyed by its text.
fn statements<'a>(
    case: &'a Case,
    seeded: &'a BTreeMap<&str, Vec<Value>>,
    view_paths: &[ViewPath],
    database: &mut Database,
) -> Result<BTreeMap<String, Statement<'a>>, ParityError> {
    let mut statements = BTreeMap::new();
    for table in &case.config.tables {
        let rows = seeded
            .get(table.name.as_str())
            .map_or(&[][..], Vec::as_slice);
        for shape in case.reads(table) {
            let reached = rows
                .iter()
                .map(|row| {
                    Ok(TargetRow {
                        row: row_name(table, &row_key(table, row)?),
                        existing: Some(row),
                        resulting: None,
                    })
                })
                .collect::<Result<_, ParityError>>()?;
            statements.insert(
                table.statement(shape),
                Statement {
                    table,
                    action: action(shape),
                    writes: false,
                    columns: column_commands(table.read_columns()),
                    rows: reached,
                },
            );
        }
    }
    for write in case.writes() {
        let table = case
            .table(&write.table)
            .ok_or_else(|| ParityError::UndeclaredTable(write.table.clone()))?;
        let rows = seeded
            .get(table.name.as_str())
            .map_or(&[][..], Vec::as_slice);
        let written = written(table, view_paths);
        for (statement, reached) in targets(table, &written, write, rows, database)? {
            statements.insert(
                statement,
                Statement {
                    table,
                    action: action(write.shape),
                    writes: true,
                    columns: column_commands(write.columns(&table.key)),
                    rows: reached,
                },
            );
        }
    }
    Ok(statements)
}

/// The relation the owner's run of a write on `table` writes, the table a view running
/// with its owner's rights writes and `table` itself otherwise.
fn written<'a>(table: &'a Table, view_paths: &[ViewPath]) -> Cow<'a, Table> {
    match view_paths
        .iter()
        .find(|path| path.view.name() == table.name)
    {
        Some(path) => Cow::Owned(Table {
            name: path.table.name().to_owned(),
            ..table.clone()
        }),
        None => Cow::Borrowed(table),
    }
}

/// Spell `write` on `table` per seeded row, or once for the table when it names no row,
/// with the rows each spelling reaches and the row the owner's run of it on `written`
/// produces.
fn targets<'a>(
    table: &Table,
    written: &Table,
    write: &Write,
    rows: &'a [Value],
    database: &mut Database,
) -> Result<Vec<(String, Vec<TargetRow<'a>>)>, ParityError> {
    match write.shape {
        Shape::Insert => {
            let key = table.row_key(|column| write.row.get(column))?;
            Ok(Vec::from([(
                table.write_statement(write, None),
                Vec::from([TargetRow {
                    row: row_name(table, &key),
                    existing: None,
                    resulting: database.resulting(&written.resulting_statement(write, None))?,
                }]),
            )]))
        }
        Shape::UpdateWithoutWhere => {
            let mut reached = Vec::new();
            for row in rows {
                reached.push(TargetRow {
                    row: row_name(table, &row_key(table, row)?),
                    existing: Some(row),
                    resulting: database
                        .resulting(&written.resulting_statement(write, Some(row)))?,
                });
            }
            Ok(Vec::from([(table.write_statement(write, None), reached)]))
        }
        _ => rows
            .iter()
            .map(|row| {
                let resulting = if write.shape == Shape::Delete {
                    None
                } else {
                    database.resulting(&written.resulting_statement(write, Some(row)))?
                };
                Ok((
                    table.write_statement(write, Some(row)),
                    Vec::from([TargetRow {
                        row: row_name(table, &row_key(table, row)?),
                        existing: Some(row),
                        resulting,
                    }]),
                ))
            })
            .collect(),
    }
}

/// Answer every probe, asking the model once per caller and statement.
async fn answer(
    model: &Model,
    case: &Case,
    statements: &BTreeMap<String, Statement<'_>>,
    probes: impl IntoIterator<Item = Probe>,
) -> Vec<EngineAnswer> {
    let mut asked: BTreeMap<(&str, &str), Vec<(&str, Answer)>> = BTreeMap::new();
    let mut answers = Vec::new();
    for probe in probes {
        let caller = case
            .config
            .callers
            .iter()
            .find(|caller| caller.name == probe.caller);
        let found = statements.get_key_value(&probe.statement);
        let answer = match (caller, found) {
            (None, _) => failed(&ProbeError::UnknownCaller(probe.caller.clone())),
            (_, None) => failed(&ProbeError::UnknownStatement(probe.statement.clone())),
            (Some(caller), Some((text, statement))) => {
                let rows = match asked.entry((caller.name.as_str(), text.as_str())) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => {
                        let rows = statement_answers(model, caller, statement).await;
                        entry.insert(rows)
                    }
                };
                rows.iter().find(|(row, _)| *row == probe.row).map_or_else(
                    || failed(&ProbeError::UnreachedRow(probe.row.clone())),
                    |(_, answer)| answer.clone(),
                )
            }
        };
        answers.push(probe.answered(answer));
    }
    answers
}

/// The model's answer for every row `statement` reaches when `caller` runs it.
///
/// A caller whose acting role lacks a privilege the statement needs fails it before any
/// row, as `PostgreSQL` does, a read with its error and a write with its SQLSTATE. Else a
/// row whose stored row passes while the row it would produce fails aborts the statement,
/// which denies every row of it.
async fn statement_answers<'a>(
    model: &Model,
    caller: &Caller,
    statement: &'a Statement<'_>,
) -> Vec<(&'a str, Answer)> {
    let refused = match model.privileged(
        &statement.table.name,
        caller,
        statement.action,
        &statement.columns,
    ) {
        Ok(true) => None,
        Ok(false) if statement.writes => Some(Answer::Rejected(INSUFFICIENT_PRIVILEGE.into())),
        Ok(false) => Some(Answer::Error(format!(
            "permission denied for table {}",
            statement.table.name
        ))),
        Err(error) => Some(failed(&error)),
    };
    if let Some(answer) = refused {
        return statement
            .rows
            .iter()
            .map(|target| (target.row.as_str(), answer.clone()))
            .collect();
    }
    let mut verdicts = Vec::with_capacity(statement.rows.len());
    for target in &statement.rows {
        let probe = RowProbe {
            existing: target.existing,
            resulting: target.resulting.as_ref(),
            columns: &statement.columns,
        };
        verdicts.push(
            model
                .permits(&statement.table.name, caller, statement.action, &probe)
                .await,
        );
    }
    let aborted = verdicts
        .iter()
        .any(|verdict| matches!(verdict, Ok(Verdict::Aborted)));
    statement
        .rows
        .iter()
        .zip(verdicts)
        .map(|(target, verdict)| {
            let answer = match verdict {
                Err(error) => failed(&error),
                Ok(Verdict::Changed) if !statement.writes => Answer::Visible,
                Ok(_) if !statement.writes => Answer::Hidden,
                Ok(Verdict::Changed) if !aborted => Answer::Changed,
                Ok(_) => Answer::Denied,
            };
            (target.row.as_str(), answer)
        })
        .collect()
}

const INSUFFICIENT_PRIVILEGE: &str = "42501";

/// An error answer carrying `error` and every cause beneath it.
fn failed(error: &dyn core::error::Error) -> Answer {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    Answer::Error(message)
}

/// The key of a seeded row.
fn row_key(table: &Table, row: &Value) -> Result<String, MissingKeyColumn> {
    table.row_key(|column| row.get(column))
}

/// A row as answers name it, its table name and key joined by a colon.
fn row_name(table: &Table, key: &str) -> String {
    format!("{}:{key}", table.name)
}

/// The statement the model answers for a shape.
fn action(shape: Shape) -> ActionStatement {
    match shape {
        Shape::Select => ActionStatement::Select,
        Shape::SelectForUpdate => ActionStatement::SelectForUpdate,
        Shape::Update => ActionStatement::Update,
        Shape::UpdateWithoutWhere => ActionStatement::UpdateWithoutWhere,
        Shape::Delete => ActionStatement::Delete,
        Shape::Insert => ActionStatement::Insert,
    }
}

/// The columns a statement touches, under the model's column commands.
fn column_commands(
    columns: BTreeMap<sql_traits::parity::ColumnCommand, Vec<String>>,
) -> BTreeMap<ColumnCommand, Vec<ColumnName>> {
    columns
        .into_iter()
        .map(|(command, columns)| {
            let command = match command {
                sql_traits::parity::ColumnCommand::Select => ColumnCommand::Select,
                sql_traits::parity::ColumnCommand::Insert => ColumnCommand::Insert,
                sql_traits::parity::ColumnCommand::Update => ColumnCommand::Update,
            };
            (
                command,
                columns.into_iter().map(ColumnName::from_stored).collect(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A probe's error answer names the failure and every cause beneath it.
    #[test]
    fn an_error_answer_carries_every_cause() {
        let error = ParityError::Resulting {
            statement: "UPDATE docs SET body = 'edited'".into(),
            source: DieselError::NotFound,
        };
        assert_eq!(
            failed(&error),
            Answer::Error(
                "running `UPDATE docs SET body = 'edited'` as the table owner: Record not found"
                    .into()
            )
        );
    }
}
