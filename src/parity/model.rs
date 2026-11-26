//! A case's translated model, loaded into its own `OpenFGA` store and asked about rows.

use alloc::{
    borrow::ToOwned,
    boxed::Box,
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
    vec::Vec,
};

use diesel::RunQueryDsl;
use openfga_client::client::{
    ConsistencyPreference, CreateStoreRequest, DeleteStoreRequest, OpenFgaClient,
    OpenFgaServiceClient, RelationshipCondition, TupleKey, TupleKeyWithoutCondition,
};
use openfga_client::prost_wkt_types::Struct;
use openfga_client::tonic::transport::Channel;
use serde_json::{json, Map, Value};
use sql_traits::parity::Caller;
use sql_traits::prelude::{Deployment, SetPacking, SettingContent, SettingValue};

use super::database::{Database, JsonbRow};
use super::{ParityError, ProbeError};
use crate::generator::tuple_generator::{TupleCondition, TupleRow};
use crate::generator::well_known::{PG_ROLE_TYPE, USER_TYPE};
use crate::json_row::JsonRow;
use crate::translator::Outputs;
use crate::types::{
    records_from_row, ActionAnswer, ActionStatement, ColumnCommand, ColumnName,
    ConditionParameterName, Record, RowNaming, RowVersion, TypeName,
};

const MAX_TUPLES_PER_WRITE: usize = 100;

/// The rows and columns one check about one statement names.
pub(super) struct RowProbe<'a> {
    /// The stored row the statement reaches, absent for an insert.
    pub(super) existing: Option<&'a Value>,
    /// The row the statement produces, absent for a read or a delete.
    pub(super) resulting: Option<&'a Value>,
    /// The columns the statement touches under each column command.
    pub(super) columns: &'a BTreeMap<ColumnCommand, Vec<ColumnName>>,
}

/// What `OpenFGA` answers for one row of a statement, split the way PostgreSQL acts on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Verdict {
    /// Every judgement holds, so the statement changes or reads the row.
    Changed,
    /// A judgement about the stored row fails, so the statement leaves the row alone,
    /// as a `USING` clause filters it.
    Skipped,
    /// The stored row passes but a judgement about the row the statement produces, or a
    /// column relation, fails, so PostgreSQL aborts the whole statement.
    Aborted,
}

/// A delimited set setting and the condition parameter its values travel under.
struct SetParameter {
    setting: String,
    parameter: String,
    delimiter: String,
}

/// The translated model in a store of its own, which [`Model::delete`] removes.
pub(super) struct Model {
    client: OpenFgaClient<Channel>,
    outputs: Outputs,
    /// The setting carrying the caller's identity.
    caller_setting: Option<String>,
    /// Every delimited set setting the deployment declares, sent split in each check.
    sets: Vec<SetParameter>,
}

/// The rows a statement naming one relation reaches, and where its privileges are checked.
struct Reach<'a> {
    /// How the translation names the rows, whose type's answers decide the statement.
    naming: &'a RowNaming,
    /// The type whose acting privileges `PostgreSQL` checks for the statement.
    privileges: &'a TypeName,
}

impl Model {
    /// Create a store named after `case`, write the model, and load the records the
    /// seeded rows state.
    pub(super) async fn create(
        service: &mut OpenFgaServiceClient<Channel>,
        case: &str,
        deployment: &Deployment,
        outputs: Outputs,
        database: &mut Database,
    ) -> Result<Self, ParityError> {
        let store_id = service
            .create_store(CreateStoreRequest {
                name: store_name(case).to_owned(),
            })
            .await
            .map_err(|status| ParityError::Openfga(Box::new(status)))?
            .into_inner()
            .id;
        let filled = Self::fill(service, &store_id, deployment, outputs, database).await;
        if filled.is_err() {
            // The failure filling the store is the one reported, and the store goes with it.
            let _ = delete_store(service, store_id).await;
        }
        filled
    }

    /// Write the model into the store `store_id` and load the records the seeded rows
    /// state.
    async fn fill(
        service: &mut OpenFgaServiceClient<Channel>,
        store_id: &str,
        deployment: &Deployment,
        outputs: Outputs,
        database: &mut Database,
    ) -> Result<Self, ParityError> {
        let model_id =
            crate::client::write_authorization_model(service, store_id, &outputs.json_model())
                .await
                .map_err(|error| ParityError::WriteModel(Box::new(error)))?;
        let client = service
            .clone()
            .into_client(store_id, &model_id)
            .set_consistency(ConsistencyPreference::HigherConsistency);
        let records = load_records(&outputs, database)?;
        for chunk in records.chunks(MAX_TUPLES_PER_WRITE) {
            let tuples = chunk.iter().map(tuple).collect::<Result<Vec<_>, _>>()?;
            client
                .write(tuples, None)
                .await
                .map_err(|error| ParityError::Tuples(Box::new(error)))?;
        }
        Ok(Self {
            client,
            outputs,
            caller_setting: caller_setting(deployment),
            sets: set_parameters(deployment),
        })
    }

    /// Delete the store.
    pub(super) async fn delete(
        self,
        service: &mut OpenFgaServiceClient<Channel>,
    ) -> Result<(), ParityError> {
        delete_store(service, self.client.store_id().to_owned()).await
    }

    /// Whether the role `caller` acts as holds every privilege `action` needs on `table`
    /// where it touches `columns`, as `PostgreSQL` checks before any row.
    pub(super) fn privileged(
        &self,
        table: &str,
        caller: &Caller,
        action: ActionStatement,
        columns: &BTreeMap<ColumnCommand, Vec<ColumnName>>,
    ) -> Result<bool, ProbeError> {
        let reach = self.reach(table)?;
        let privileges = self
            .outputs
            .translation()
            .acting_privileges()
            .iter()
            .find(|held| &held.type_name == reach.privileges && held.role == caller.role)
            .ok_or_else(|| ProbeError::NoPrivileges(caller.role.clone()))?;
        Ok(privileges.permits(action, columns))
    }

    /// The rows a statement naming `table` reaches, and where `PostgreSQL` checks its
    /// privileges.
    ///
    /// A view running with its owner's rights reaches the rows of the table it writes,
    /// answered by that table's answers, while its privileges are checked on the view.
    fn reach(&self, table: &str) -> Result<Reach<'_>, ProbeError> {
        let translation = self.outputs.translation();
        let namings = translation.row_naming();
        if let Some(naming) = namings.iter().find(|naming| naming.table.name() == table) {
            return Ok(Reach {
                naming,
                privileges: &naming.type_name,
            });
        }
        let unnamed = || ProbeError::NoRowNaming(table.to_owned());
        let path = translation
            .view_paths()
            .iter()
            .find(|path| path.view.name() == table)
            .ok_or_else(unnamed)?;
        let naming = namings
            .iter()
            .find(|naming| naming.table == path.table)
            .ok_or_else(unnamed)?;
        Ok(Reach {
            naming,
            privileges: &path.type_name,
        })
    }

    /// Ask the emitted answer for `action` on `table` about the rows and columns `probe` names.
    ///
    /// An answer with several paths changes the row where any path does, and otherwise
    /// leaves it alone where any path only filters it.
    pub(super) async fn permits(
        &self,
        table: &str,
        caller: &Caller,
        action: ActionStatement,
        probe: &RowProbe<'_>,
    ) -> Result<Verdict, ProbeError> {
        let naming = self.reach(table)?.naming;
        let entry = self
            .outputs
            .translation()
            .action_relations()
            .iter()
            .find(|entry| entry.type_name == naming.type_name && entry.statement == action)
            .ok_or(ProbeError::NoAnswer(action))?;
        let caller = self.request(caller)?;
        let ActionAnswer::AnyOf(paths) = &entry.answer else {
            return self.path(&entry.answer, naming, probe, &caller).await;
        };
        let mut verdict = Verdict::Aborted;
        for path in paths {
            match self.path(path, naming, probe, &caller).await? {
                Verdict::Changed => return Ok(Verdict::Changed),
                Verdict::Skipped => verdict = Verdict::Skipped,
                Verdict::Aborted => {}
            }
        }
        Ok(verdict)
    }

    /// Ask one path of an answer about the rows and columns `probe` names.
    async fn path(
        &self,
        answer: &ActionAnswer,
        naming: &RowNaming,
        probe: &RowProbe<'_>,
        caller: &Request,
    ) -> Result<Verdict, ProbeError> {
        let ActionAnswer::ByColumn(columns) = answer else {
            return self.rows(answer, naming, probe, caller).await;
        };
        let rows = self.rows(&columns.rows, naming, probe, caller).await?;
        if rows != Verdict::Changed {
            return Ok(rows);
        }
        for command in &columns.commands {
            let touched = probe
                .columns
                .get(&command.command)
                .ok_or(ProbeError::NoColumns(command.command))?;
            for column in touched {
                if !self
                    .check(
                        command.relation(column).as_str(),
                        &columns.gate,
                        caller,
                        Vec::new(),
                    )
                    .await?
                {
                    return Ok(Verdict::Aborted);
                }
            }
        }
        Ok(Verdict::Changed)
    }

    /// Interpret the answer about the rows without inferring relations. The stored row's
    /// judgements are asked first, since a row they filter is never checked further.
    ///
    /// The stored row is named under each judgement's own type by the table's key, since
    /// a path through a view asks about the table's rows on a type of its own.
    async fn rows(
        &self,
        answer: &ActionAnswer,
        naming: &RowNaming,
        probe: &RowProbe<'_>,
        caller: &Request,
    ) -> Result<Verdict, ProbeError> {
        let judgements = match answer {
            ActionAnswer::Unrestricted => return Ok(Verdict::Changed),
            ActionAnswer::Denied => return Ok(Verdict::Skipped),
            ActionAnswer::Judged(judgements) => judgements,
            other => return Err(ProbeError::Unsupported(format!("{other:?}"))),
        };
        let (stored, produced): (Vec<_>, Vec<_>) = judgements
            .iter()
            .partition(|judgement| judgement.version == RowVersion::Existing);
        for judgement in stored {
            let row = probe.existing.ok_or(ProbeError::NoStoredRow)?;
            let object = naming
                .render_as(&judgement.type_name, &JsonRow(row))?
                .ok_or(ProbeError::Unnamed)?;
            if !self
                .check(judgement.relation.as_str(), &object, caller, Vec::new())
                .await?
            {
                return Ok(Verdict::Skipped);
            }
        }
        for judgement in produced {
            if judgement.version != RowVersion::Resulting {
                return Err(ProbeError::Unsupported(format!("{:?}", judgement.version)));
            }
            let row = probe.resulting.ok_or(ProbeError::NoResultingRow)?;
            let resulting = self
                .outputs
                .translation()
                .resulting_rows()
                .iter()
                .find(|resulting| resulting.type_name == judgement.type_name)
                .ok_or(ProbeError::NoResultingNaming)?;
            let object = resulting
                .object(&JsonRow(row))?
                .ok_or(ProbeError::Unnamed)?;
            let records = resulting
                .records(&JsonRow(row))?
                .iter()
                .map(tuple)
                .collect::<Result<Vec<_>, _>>()?;
            if !self
                .check(judgement.relation.as_str(), &object, caller, records)
                .await?
            {
                return Ok(Verdict::Aborted);
            }
        }
        Ok(Verdict::Changed)
    }

    /// The user, acting role and context every check of `caller` carries.
    fn request(&self, caller: &Caller) -> Result<Request, ProbeError> {
        let setting = self
            .caller_setting
            .as_deref()
            .ok_or(ProbeError::NoCallerSetting)?;
        let identity = setting_value(caller, setting)?;
        let user = format!("{USER_TYPE}:{identity}");
        let mut context = Map::new();
        context.insert("settings".into(), json!(caller.settings));
        for set in &self.sets {
            let values: Vec<&str> = setting_value(caller, &set.setting)?
                .split(set.delimiter.as_str())
                .filter(|item| !item.is_empty())
                .collect();
            context.insert(set.parameter.clone(), json!(values));
        }
        Ok(Request {
            acting: TupleKey {
                user: user.clone(),
                relation: "usage".into(),
                object: format!("{PG_ROLE_TYPE}:{}", caller.role),
                condition: None,
            },
            user,
            context: serde_json::from_value(Value::Object(context))?,
        })
    }

    /// Carry the acting role and `records` as contextual tuples on the check.
    async fn check(
        &self,
        relation: &str,
        object: &str,
        caller: &Request,
        mut records: Vec<TupleKey>,
    ) -> Result<bool, ProbeError> {
        records.push(caller.acting.clone());
        self.client
            .check(
                TupleKeyWithoutCondition {
                    user: caller.user.clone(),
                    relation: relation.to_owned(),
                    object: object.to_owned(),
                },
                records,
                caller.context.clone(),
                false,
            )
            .await
            .map_err(|error| ProbeError::Check(Box::new(error)))
    }
}

/// Delete the store `store_id` with everything in it.
async fn delete_store(
    service: &mut OpenFgaServiceClient<Channel>,
    store_id: String,
) -> Result<(), ParityError> {
    service
        .delete_store(DeleteStoreRequest { store_id })
        .await
        .map_err(|status| ParityError::Openfga(Box::new(status)))?;
    Ok(())
}

/// What every check one caller makes carries.
struct Request {
    user: String,
    acting: TupleKey,
    context: Struct,
}

/// The value `caller` sets for `setting`.
fn setting_value<'caller>(
    caller: &'caller Caller,
    setting: &str,
) -> Result<&'caller str, ProbeError> {
    caller
        .settings
        .get(setting)
        .map(String::as_str)
        .ok_or_else(|| ProbeError::UnsetSetting {
            caller: caller.name.clone(),
            setting: setting.to_owned(),
        })
}

/// The setting the deployment declares as the caller's identity.
fn caller_setting(deployment: &Deployment) -> Option<String> {
    deployment
        .settings()
        .iter()
        .find(|setting| {
            matches!(
                setting.content(),
                SettingContent::Value(SettingValue::Caller(_))
            )
        })
        .map(|setting| setting.name().to_owned())
}

/// Every delimited set setting the deployment declares.
fn set_parameters(deployment: &Deployment) -> Vec<SetParameter> {
    deployment
        .settings()
        .iter()
        .filter_map(|setting| match setting.content() {
            SettingContent::Value(SettingValue::Set {
                packing: SetPacking::Delimited(delimiter),
                ..
            }) => Some(SetParameter {
                setting: setting.name().to_owned(),
                parameter: ConditionParameterName::derived(setting.name()).into(),
                delimiter: delimiter.clone(),
            }),
            _ => None,
        })
        .collect()
}

/// A store name the service accepts, which caps them at 64 characters.
fn store_name(case: &str) -> &str {
    let from = case.char_indices().rev().nth(63).map_or(0, |(at, _)| at);
    case.get(from..).unwrap_or(case)
}

/// Load pure row descriptions and execute the remaining tuple queries.
fn load_records(outputs: &Outputs, database: &mut Database) -> Result<Vec<Record>, ParityError> {
    let mut records = BTreeSet::new();
    let mut rows: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for query in outputs.tuple_queries() {
        if query.skipped.is_some() {
            continue;
        }
        if let Some(description) = &query.description {
            if let Some(table) = description.row_table() {
                let table_rows = match rows.entry(table.sql_name()) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => {
                        let loaded = database.rows(entry.key())?;
                        entry.insert(loaded)
                    }
                };
                for row in table_rows.iter() {
                    records.extend(records_from_row(description, &JsonRow(row))?);
                }
                continue;
            }
        }
        // The translator supplies the tuple query and its runtime result shape, so no
        // `table!` schema exists for it.
        let tuples = diesel::sql_query(format!(
            "SELECT to_jsonb(t) AS row FROM ({}) t",
            query.sql.trim().trim_end_matches(';')
        ))
        .load::<JsonbRow>(database.connection())?;
        for JsonbRow { row } in tuples {
            let context = row.get("context").map(Value::to_string);
            let condition = match query.condition {
                Some(_) => Some(TupleCondition {
                    name: column(&row, "condition")?,
                    context: context
                        .as_deref()
                        .ok_or(ParityError::TupleColumn("context"))?,
                }),
                None => None,
            };
            records.insert(outputs.record_from_tuple_row(TupleRow {
                object: column(&row, "object")?,
                relation: column(&row, "relation")?,
                subject: column(&row, "subject")?,
                condition,
            })?);
        }
    }
    Ok(records.into_iter().collect())
}

/// The text column `name` of a tuple query's row.
fn column<'row>(row: &'row Value, name: &'static str) -> Result<&'row str, ParityError> {
    row.get(name)
        .and_then(Value::as_str)
        .ok_or(ParityError::TupleColumn(name))
}

/// Serialize the record without changing its relation or subject.
fn tuple(record: &Record) -> Result<TupleKey, serde_json::Error> {
    Ok(TupleKey {
        user: record.subject.clone(),
        relation: record.relation.as_str().to_owned(),
        object: record.object.clone(),
        condition: match &record.context {
            Some(context) => Some(RelationshipCondition {
                name: context.condition.as_str().to_owned(),
                context: Some(serde_json::from_value(json!(context.values))?),
            }),
            None => None,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ConditionName, RecordContextValue, RelationName};

    /// Tuple serialization preserves emitted names and optional condition context.
    #[test]
    fn record_context_is_preserved() {
        let mut record = Record {
            object: "doc:1".into(),
            relation: RelationName::canonicalized("owner"),
            subject: "user:alice".into(),
            context: None,
        };
        let plain = tuple(&record).unwrap();
        assert_eq!(
            (
                plain.object.as_str(),
                plain.relation.as_str(),
                plain.user.as_str()
            ),
            ("doc:1", "owner", "user:alice")
        );
        assert_eq!(plain.condition, None);
        record.context = Some(RecordContextValue {
            condition: ConditionName::canonicalized("owner_matches"),
            values: BTreeMap::from([("owner".into(), "alice".into())]),
        });
        let condition = tuple(&record).unwrap().condition.unwrap();
        assert_eq!(condition.name, "owner_matches");
        assert_eq!(
            serde_json::to_value(condition.context.unwrap()).unwrap(),
            json!({"owner":"alice"})
        );
    }

    /// A store name keeps the tail of a long case name, which tells generated cases apart.
    #[test]
    fn store_names_fit() {
        assert_eq!(store_name("short"), "short");
        let long = format!("{}tail", "x".repeat(70));
        assert_eq!(store_name(&long).len(), 64);
        assert!(store_name(&long).ends_with("tail"));
    }
}
