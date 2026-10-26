use crate::classifier::patterns::{AttributeLiteral, AttributeTest};
#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;

#[cfg(test)]
use crate::classifier::patterns::{ClassifiedExpr, PatternClass};
use crate::generator::db_lookup::resolve_row_identity;
use crate::generator::identity::{
    typed_name_literal, typed_name_sql, wildcard_subject_literal, MAX_OBJECT_NAME_CHARS,
    MAX_SUBJECT_NAME_BYTES,
};
use crate::generator::ir::{MembershipGate, TupleSource, TupleSourceKey};
use crate::generator::model_generator::{DirectSubject, SchemaPlan};
pub use crate::generator::notes::SkippedTuples;
use crate::generator::well_known::{
    deny_relation, WellKnownTypes, ARRAY_ELEMENT_ALIAS, HOLDER_OBJECT_ID,
};
use crate::parser::names::{table_id_has_column, table_identity};
use crate::parser::sql_parser::{ColumnLike, DatabaseLike, TableLike};
use crate::types::{ColumnName, ConditionName, ContextWitness, RelationName, TableId, TypeName};
use crate::types::{Record, RecordContextValue, RecordDescription};
use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Write;
use sql_traits::utils::scalar_family::ScalarFamily;

#[cfg(test)]
std::thread_local! {
    static UNBOUNDED_COLUMNS_RESOLUTIONS: core::cell::Cell<usize> =
        const { core::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_unbounded_columns_resolutions() {
    UNBOUNDED_COLUMNS_RESOLUTIONS.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn unbounded_columns_resolutions() -> usize {
    UNBOUNDED_COLUMNS_RESOLUTIONS.with(core::cell::Cell::get)
}

/// A generated tuple query with its descriptive comment.
#[derive(Debug, Clone)]
pub struct TupleQuery {
    /// Human-readable SQL comment describing what this query populates.
    pub comment: String,
    /// SELECT statement that produces (object, relation, subject) triples.
    pub sql: String,
    /// The same records as structure, so a caller holding one row's values
    /// reaches them without a database. `None` where the query produces no
    /// records, which is a gap alone.
    pub description: Option<RecordDescription>,
    /// Condition the rows carry, when the query yields the two extra columns a
    /// conditional tuple needs. `None` means three columns and no condition, so a
    /// loader knows the shape without parsing the SQL.
    pub condition: Option<ConditionName>,
    /// The gap this entry stands for, where no statement could be built. `sql` is then
    /// advice rather than something to run: executing it loads nothing and succeeds.
    pub skipped: Option<SkippedTuples>,
}

/// Format a list of tuple queries into a single SQL string.
pub fn format_tuples(tuples: &[TupleQuery]) -> String {
    let mut out = String::new();
    for query in tuples {
        out.push_str(&query.comment);
        out.push('\n');
        out.push_str(&query.sql);
        out.push_str("\n\n");
    }
    let trimmed = out.trim_end_matches('\n');
    if trimmed.is_empty() {
        return String::new();
    }
    let mut result =
        "SET TIME ZONE 'UTC';\nSET DateStyle = 'ISO, MDY';\nSET bytea_output = 'hex';\n\n"
            .to_string();
    result.push_str(trimmed);
    result.push('\n');
    result
}

/// One row of a [`TupleQuery`]'s result, named as the query projects it.
#[derive(Debug, Clone, Copy)]
pub struct TupleRow<'a> {
    /// The `object` column.
    pub object: &'a str,
    /// The `relation` column.
    pub relation: &'a str,
    /// The `subject` column.
    pub subject: &'a str,
    /// The `condition` and `context` columns, which a query projects together or
    /// not at all. `Some` exactly when [`TupleQuery::condition`] is.
    pub condition: Option<TupleCondition<'a>>,
}

/// The two columns a conditional query adds.
#[derive(Debug, Clone, Copy)]
pub struct TupleCondition<'a> {
    /// The `condition` column, the condition the tuple names.
    pub name: &'a str,
    /// The `context` column, as JSON text of the object the query builds.
    pub context: &'a str,
}

/// Why a row does not spell a record.
///
/// `#[non_exhaustive]`: every arm is a refusal, so a caller's wildcard arm still
/// falls closed, and a later reason costs it no rewrite.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TupleRowError {
    /// The object names a type the model does not define.
    UnknownType(String),
    /// The type defines no such relation.
    UnknownRelation {
        /// Type the object names.
        type_name: TypeName,
        /// Relation the row names.
        relation: String,
    },
    /// The relation is computed from others, so no tuple is written on it.
    RelationTakesNoTuples {
        /// Type the object names.
        type_name: TypeName,
        /// Relation the row names.
        relation: String,
    },
    /// The object is not a `type:key` name.
    MalformedObject(String),
    /// The subject is not a `type:key` name.
    MalformedSubject(String),
    /// The context is not a non-empty object of scalars.
    MalformedContext(String),
    /// The relation is the one the model denies with. Nothing populates it, so a row
    /// naming it is a mistake, and reading it back would hand the caller a fact the
    /// service itself refuses.
    RelationGrantsNobody {
        /// Type the object names.
        type_name: TypeName,
        /// Relation the row names.
        relation: String,
    },
    /// The relation does not accept tuples under the condition the row names, or
    /// grants nothing without one. Taking the row at face value would grant what
    /// the model does not.
    ConditionMismatch {
        /// Type the object names.
        type_name: TypeName,
        /// Relation the row names.
        relation: String,
        /// The condition the row named, absent where it named none.
        named: Option<String>,
    },
}

impl core::fmt::Display for TupleRowError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownType(name) => write!(f, "the model defines no type {name}"),
            Self::UnknownRelation {
                type_name,
                relation,
            } => write!(f, "the model defines no {relation} on {type_name}"),
            Self::RelationTakesNoTuples {
                type_name,
                relation,
            } => write!(
                f,
                "{type_name}'s {relation} is computed from other relations, so it takes no tuples"
            ),
            Self::MalformedObject(name) => write!(f, "the object {name} is not a type:key name"),
            Self::MalformedSubject(name) => write!(f, "the subject {name} is not a type:key name"),
            Self::MalformedContext(text) => {
                write!(f, "the context {text} is not a non-empty object of scalars")
            }
            Self::RelationGrantsNobody {
                type_name,
                relation,
            } => write!(
                f,
                "{type_name}'s {relation} grants nobody, so it takes no tuple"
            ),
            Self::ConditionMismatch {
                type_name,
                relation,
                named: Some(condition),
            } => write!(
                f,
                "{type_name}'s {relation} accepts no tuple under condition {condition}"
            ),
            Self::ConditionMismatch {
                type_name,
                relation,
                named: None,
            } => write!(
                f,
                "{type_name}'s {relation} grants nothing without a condition"
            ),
        }
    }
}

impl core::error::Error for TupleRowError {}

/// Read one row of a tuple query back as the record it spells.
pub(crate) fn record_from_tuple_row(
    plan: &SchemaPlan,
    row: TupleRow<'_>,
) -> Result<Record, TupleRowError> {
    let Some((object_type, _)) = row.object.split_once(':') else {
        return Err(TupleRowError::MalformedObject(row.object.to_string()));
    };
    if !row.subject.contains(':') {
        return Err(TupleRowError::MalformedSubject(row.subject.to_string()));
    }
    let Some(type_plan) = plan
        .types
        .iter()
        .find(|type_plan| type_plan.type_name == *object_type)
    else {
        return Err(TupleRowError::UnknownType(object_type.to_string()));
    };
    if row.relation == deny_relation().as_str() {
        // Nothing populates the denial, and the model points it at a type no caller is, so
        // a row naming it is a mistake rather than a fact. Refusing here closes the crate's
        // own door as well as the service's.
        return Err(TupleRowError::RelationGrantsNobody {
            type_name: type_plan.type_name.clone(),
            relation: row.relation.to_string(),
        });
    }
    let Some((relation, subjects)) = type_plan.direct_relations.get_key_value(row.relation) else {
        let type_name = type_plan.type_name.clone();
        let relation = row.relation.to_string();
        return Err(if type_plan.computed_relations.contains_key(row.relation) {
            TupleRowError::RelationTakesNoTuples {
                type_name,
                relation,
            }
        } else {
            TupleRowError::UnknownRelation {
                type_name,
                relation,
            }
        });
    };

    Ok(Record {
        object: row.object.to_string(),
        relation: relation.clone(),
        subject: row.subject.to_string(),
        context: row_context(&row, &type_plan.type_name, relation, subjects)?,
    })
}

/// The context the row carries, once the relation is known to accept it.
fn row_context(
    row: &TupleRow<'_>,
    object_type: &TypeName,
    relation: &RelationName,
    subjects: &[DirectSubject],
) -> Result<Option<RecordContextValue>, TupleRowError> {
    let mismatch = |named: Option<&str>| TupleRowError::ConditionMismatch {
        type_name: object_type.clone(),
        relation: relation.to_string(),
        named: named.map(ToString::to_string),
    };
    let Some(condition) = row.condition else {
        return if subjects
            .iter()
            .any(|subject| matches!(subject, DirectSubject::Type(_) | DirectSubject::Wildcard(_)))
        {
            Ok(None)
        } else {
            Err(mismatch(None))
        };
    };
    let Some(named) = subjects.iter().find_map(|subject| match subject {
        DirectSubject::ConditionalWildcard {
            condition: named, ..
        }
        | DirectSubject::ConditionalType {
            condition: named, ..
        } => (named == condition.name).then_some(named),
        DirectSubject::Type(_) | DirectSubject::Wildcard(_) => None,
    }) else {
        return Err(mismatch(Some(condition.name)));
    };
    let values = context_entries(condition.context)
        .ok_or_else(|| TupleRowError::MalformedContext(condition.context.to_string()))?;
    Ok(Some(RecordContextValue {
        condition: named.clone(),
        values,
    }))
}

/// Every key and scalar a conditional tuple's context holds, rendered as the tuple
/// SQL renders it. [`None`] for an empty or non-scalar context, which no conditional
/// tuple should carry.
fn context_entries(context: &str) -> Option<BTreeMap<String, String>> {
    let parsed: serde_json::Value = serde_json::from_str(context).ok()?;
    let object = parsed.as_object()?;
    let mut values = BTreeMap::new();
    for (key, value) in object {
        let text = match value {
            serde_json::Value::String(text) => text.clone(),
            serde_json::Value::Number(number) => number.to_string(),
            serde_json::Value::Bool(flag) => (if *flag { "true" } else { "false" }).to_string(),
            _ => return None,
        };
        values.insert(key.clone(), text);
    }
    (!values.is_empty()).then_some(values)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RenderedSourceKey<'a> {
    owner: Option<(&'a TypeName, bool)>,
    source: TupleSourceKey<'a>,
}

#[derive(Debug)]
pub(crate) struct GeneratedTupleQueries<'a> {
    pub(crate) queries: Vec<TupleQuery>,
    pub(crate) descriptions: BTreeMap<RenderedSourceKey<'a>, Option<RecordDescription>>,
}

pub(crate) fn rendered_source_key<'a>(
    source: &'a TupleSource,
    owner_type: &'a TypeName,
    only_own_rows: bool,
) -> RenderedSourceKey<'a> {
    RenderedSourceKey {
        owner: source
            .emits_owner_type_objects()
            .then_some((owner_type, only_own_rows)),
        source: source.dedup_key(),
    }
}

/// Generate tuple SQL queries from a pre-built [`SchemaPlan`].
pub(crate) fn generate_tuple_queries_from_plan<'plan, DB: DatabaseLike>(
    plan: &'plan SchemaPlan,
    bounds: &UnboundedColumns,
    db: &DB,
) -> GeneratedTupleQueries<'plan> {
    let mut queries = Vec::new();
    let mut descriptions = BTreeMap::new();
    let grantable = crate::generator::model_generator::grantable_relations(&plan.types);

    for type_plan in &plan.types {
        for source in &type_plan.table_tuple_sources {
            let fed = source.feeds(&type_plan.type_name);
            if !fed.is_empty() && !fed.iter().any(|target| grantable.contains(target)) {
                continue;
            }
            let key = rendered_source_key(
                source,
                &type_plan.type_name,
                type_plan.reads_only_its_own_rows,
            );
            if descriptions.contains_key(&key) {
                continue;
            }
            let Some(query) = render_tuple_source(
                source,
                &type_plan.type_name,
                type_plan.reads_only_its_own_rows,
                &plan.well_known,
                NameContext::new(bounds),
                db,
            ) else {
                descriptions.insert(key, None);
                continue;
            };
            descriptions.insert(key, query.description.clone());
            queries.push(query);
        }
    }

    GeneratedTupleQueries {
        queries,
        descriptions,
    }
}

/// What identifies the objects a tuple query produces.
#[derive(Clone, Copy)]
struct ObjectSource<'a> {
    table: &'a TableId,
    /// `OpenFGA` type the objects belong to.
    type_name: &'a TypeName,
    /// Columns supplying the object identifier, in declared order.
    identity_cols: &'a [ColumnName],
    /// Read `FROM ONLY`, keeping inheritance children's rows out.
    only_own_rows: bool,
}

/// Each key column quoted, in declared order.
fn quoted_key_parts(identity_cols: &[ColumnName]) -> Vec<String> {
    identity_cols
        .iter()
        .map(|c| quote_sql_identifier(c.as_str()))
        .collect()
}

/// `IS NOT NULL` over every part of a key, and the rendered name fitting the
/// target where a value of that type could overrun it.
///
/// A compound key needs every column present: one NULL part leaves the row with
/// no name, exactly as one NULL column left a single-column row unnamed. The
/// length half falls closed rather than shortening the name, since two rows
/// shortened alike become one object holding both grants.
fn row_is_nameable(
    parts: &[String],
    object_sql: &str,
    table: &TableId,
    columns: &[ColumnName],
    names: NameContext<'_>,
) -> String {
    let mut guard = parts
        .iter()
        .map(|part| format!("{part} IS NOT NULL"))
        .collect::<Vec<_>>()
        .join(" AND ");
    if names.any_unbounded(table, columns) {
        let _ = write!(
            guard,
            " AND length({object_sql}) <= {MAX_OBJECT_NAME_CHARS}"
        );
    }
    guard
}

/// `base` extended with the fit guards for a shape whose names both come from a
/// joined table's columns. Returns the extension alone when `base` is empty.
fn join_row_is_nameable(
    base: &str,
    object_sql: &str,
    subject_sql: Option<&str>,
    table: &TableId,
    object_columns: &[ColumnName],
    subject_columns: &[ColumnName],
    names: NameContext<'_>,
) -> String {
    let mut out = base.to_string();
    let mut push = |guard: String| {
        if out.is_empty() {
            out = format!("\nAND {guard}");
        } else {
            let _ = write!(out, "\nAND {guard}");
        }
    };
    if names.any_unbounded(table, object_columns) {
        push(format!("length({object_sql}) <= {MAX_OBJECT_NAME_CHARS}"));
    }
    if let Some(subject_sql) = subject_sql {
        if let Some(guard) = subject_fits(subject_sql, table, subject_columns, names) {
            push(guard);
        }
    }
    out
}

/// The subject name fits the target.
///
/// Bytes rather than characters: the two limits differ in unit, and using one
/// for the other drops a fitting non-ASCII subject or lets an over-long one
/// reach the service.
fn subject_fits(
    subject_sql: &str,
    table: &TableId,
    columns: &[ColumnName],
    names: NameContext<'_>,
) -> Option<String> {
    names
        .any_unbounded(table, columns)
        .then(|| format!("octet_length({subject_sql}) <= {MAX_SUBJECT_NAME_BYTES}"))
}

/// Derive the three values every owner-type match arm needs from the same inputs.
/// Returns `(table_sql, object_sql, key_not_null)`.
fn owner_object_sql(
    owner_type: &TypeName,
    table: &TableId,
    identity_cols: &[ColumnName],
    only_own_rows: bool,
    names: NameContext<'_>,
) -> (String, String, String) {
    let identity_parts = quoted_key_parts(identity_cols);
    let object_sql = typed_name_sql(owner_type, identity_parts.iter().map(String::as_str));
    let key_not_null = row_is_nameable(&identity_parts, &object_sql, table, identity_cols, names);
    let table_sql = owner_table_reference(table, only_own_rows);
    (table_sql, object_sql, key_not_null)
}

/// Wrap `subject_fits` into a ready-to-append SQL fragment `"\nAND <guard>"`,
/// or an empty string when the subject column is bounded.
fn subject_fits_guard(
    subject_sql: &str,
    table: &TableId,
    columns: &[ColumnName],
    names: NameContext<'_>,
) -> String {
    subject_fits(subject_sql, table, columns, names)
        .map_or_else(String::new, |guard| format!("\nAND {guard}"))
}

#[derive(Clone, Copy)]
pub(crate) struct NameContext<'a> {
    bounds: &'a UnboundedColumns,
}

impl<'a> NameContext<'a> {
    pub(crate) const fn new(bounds: &'a UnboundedColumns) -> Self {
        Self { bounds }
    }

    fn any_unbounded(self, table: &TableId, columns: &[ColumnName]) -> bool {
        self.bounds.any_unbounded(table, columns)
    }
}

/// Columns whose declared type could render a name longer than the target accepts,
/// resolved once for the whole schema.
///
/// Asked per source it went through `lookup_table`, which walks every table and
/// allocates per comparison, and that turned tuple generation from 2.6ms into 24.9ms
/// at 400 tables. One pass over the tables answers every arm instead.
#[derive(Debug, Default)]
pub(crate) struct UnboundedColumns {
    /// Table spelling to the columns of it no bounded type covers. A table absent
    /// here is unknown rather than bounded, so its guard is emitted.
    by_table: BTreeMap<TableId, BTreeSet<String>>,
}

impl UnboundedColumns {
    /// Resolve every table's unbounded columns in one pass.
    pub(crate) fn resolve<DB: DatabaseLike>(db: &DB) -> Self {
        #[cfg(test)]
        UNBOUNDED_COLUMNS_RESOLUTIONS.with(|count| count.set(count.get() + 1));
        let mut by_table: BTreeMap<TableId, BTreeSet<String>> = BTreeMap::new();
        for table in db.tables() {
            let unbounded: BTreeSet<String> = table
                .columns(db)
                .into_iter()
                .flatten()
                .filter(|c| !is_bounded_short_family(c.scalar_family(db)))
                .map(|c| c.stored_column_name().into_owned())
                .collect();
            by_table.insert(table_identity(table), unbounded);
        }
        Self { by_table }
    }

    /// Whether any of `columns` could render a name longer than the target accepts.
    ///
    /// A table this cannot resolve answers yes: the guard is added on suspicion
    /// rather than left off on it.
    pub(crate) fn any_unbounded(&self, table: &TableId, columns: &[ColumnName]) -> bool {
        let Some(unbounded) = self.by_table.get(table) else {
            return true;
        };
        columns
            .iter()
            .any(|column| unbounded.contains(column.as_str()))
    }
}

/// Types whose text form is short enough that no encoding of them can overrun.
fn is_bounded_short_family(family: Option<ScalarFamily>) -> bool {
    matches!(
        family,
        Some(
            ScalarFamily::Bool
                | ScalarFamily::Int
                | ScalarFamily::Uuid
                | ScalarFamily::Date
                | ScalarFamily::Timestamp
                | ScalarFamily::TimestampTz
        )
    )
}

fn render_ownership_tuple_source(
    object: ObjectSource<'_>,
    owner_col: &ColumnName,
    relation: &RelationName,
    subject_prefix: &TypeName,
    comment: String,
    owner_filter: Option<(&TableId, &ColumnName)>,
    names: NameContext<'_>,
) -> TupleQuery {
    let ObjectSource {
        table,
        type_name: table_type,
        identity_cols,
        only_own_rows,
    } = object;
    let table_sql = owner_table_reference(table, only_own_rows);
    let identity_parts = quoted_key_parts(identity_cols);
    let owner_col_sql = quote_sql_identifier(owner_col.as_str());
    let object_sql = typed_name_sql(table_type, identity_parts.iter().map(String::as_str));
    let subject_sql = typed_name_sql(subject_prefix, [owner_col_sql.as_str()]);

    let owner_cols = [owner_col.clone()];
    let nameable = row_is_nameable(&identity_parts, &object_sql, table, identity_cols, names);
    let subject_guard = subject_fits_guard(&subject_sql, table, &owner_cols, names);
    // The owner column is the key itself where an identity names both sides, and stating
    // one predicate twice is noise in a script an operator reads.
    let mut predicates: Vec<&str> = Vec::new();
    let owner_not_null = format!("{owner_col_sql} IS NOT NULL");
    let principal_filter = owner_filter.map(|(principal_table, principal_identity_col)| {
        let principal_table_sql = principal_table.sql_name();
        let principal_identity_col_sql = quote_sql_identifier(principal_identity_col.as_str());
        format!(
            "{owner_col_sql} IN (SELECT {principal_identity_col_sql} FROM {principal_table_sql})"
        )
    });
    if let Some(filter) = &principal_filter {
        predicates.push(filter);
    }
    predicates.push(&owner_not_null);
    if nameable != owner_not_null {
        predicates.push(&nameable);
    }
    let where_clause = format!("WHERE {}{subject_guard};", predicates.join("\nAND "));

    TupleQuery {
        comment,
        sql: format!(
            "SELECT {object_sql} AS object, '{relation}' AS relation, \
             {subject_sql} AS subject\n\
             FROM {table_sql}\n\
             {where_clause}"
        ),
        description: None,
        condition: None,
        skipped: None,
    }
}

/// Reduce `text` to a single `--` comment line.
///
/// `PostgreSQL` identifiers may contain newlines and comments interpolate table,
/// column, and role names, so without this the tail of an identifier executes as
/// SQL. A missing `--` marker would do the same, so it is restored.
fn single_comment_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 3);
    let mut previous_was_space = false;
    for ch in text.chars() {
        let ch = if ch.is_control() { ' ' } else { ch };
        if ch == ' ' {
            if previous_was_space {
                continue;
            }
            previous_was_space = true;
        } else {
            previous_was_space = false;
        }
        out.push(ch);
    }

    let squeezed = out.trim();
    if squeezed.starts_with("--") {
        squeezed.to_string()
    } else {
        format!("-- {squeezed}")
    }
}

/// Enforce the "comments stay comments" invariant. Every [`TupleQuery`] in the
/// crate passes through here, so new [`TupleSource`] variants inherit it.
fn sanitize_tuple_query(mut query: TupleQuery) -> TupleQuery {
    query.comment = single_comment_line(&query.comment);
    if query.skipped.is_some() {
        query.sql = single_comment_line(&query.sql);
    }
    query
}

/// Render one [`TupleSource`].
///
/// Variants emitting objects of their own table MUST use `owner_type`: re-deriving
/// a name from `table` files one table's tuples under a colliding table's type.
fn render_tuple_source<DB: DatabaseLike>(
    source: &TupleSource,
    owner_type: &TypeName,
    only_own_rows: bool,
    well_known: &WellKnownTypes,
    names: NameContext<'_>,
    db: &DB,
) -> Option<TupleQuery> {
    let mut query = sanitize_tuple_query(render_tuple_source_inner(
        source,
        owner_type,
        only_own_rows,
        well_known,
        names,
        db,
    )?);
    // Every query passes through here, so a new variant reaches the describer
    // rather than silently shipping without a description.
    let description = crate::generator::describe::describe_tuple_source(
        source, owner_type, &query, well_known, db,
    );
    query.description = description;
    Some(query)
}

pub(crate) fn render_tuple_source_inner<DB: DatabaseLike>(
    source: &TupleSource,
    owner_type: &TypeName,
    only_own_rows: bool,
    well_known: &WellKnownTypes,
    names: NameContext<'_>,
    db: &DB,
) -> Option<TupleQuery> {
    let wildcard_subject = wildcard_subject_literal(&well_known.user);
    match source {
        TupleSource::DirectOwnership {
            table,
            identity_cols,
            owner_col,
            relation,
        } => Some(render_ownership_tuple_source(
            ObjectSource {
                table,
                type_name: owner_type,
                identity_cols,
                only_own_rows,
            },
            owner_col,
            relation,
            &well_known.user,
            format!("-- User ownership ({owner_col} references users)"),
            None,
            names,
        )),

        TupleSource::ArrayMembership {
            table,
            identity_cols,
            array_col,
            relation,
        } => {
            let array_col_sql = quote_sql_identifier(array_col.as_str());
            let subject_sql = typed_name_sql(&well_known.user, [ARRAY_ELEMENT_ALIAS]);
            let (table_sql, object_sql, nameable) =
                owner_object_sql(owner_type, table, identity_cols, only_own_rows, names);
            let subject_guard =
                subject_fits_guard(&subject_sql, table, core::slice::from_ref(array_col), names);
            Some(TupleQuery {
                comment: format!("-- Array membership (elements of {array_col} reference users)"),
                sql: format!(
                    "SELECT {object_sql} AS object, '{relation}' AS relation, \
                     {subject_sql} AS subject\n\
                     FROM {table_sql}\n\
                     CROSS JOIN UNNEST({array_col_sql}) AS {ARRAY_ELEMENT_ALIAS}\n\
                     WHERE {ARRAY_ELEMENT_ALIAS} IS NOT NULL\n\
                     AND {nameable}{subject_guard};"
                ),
                description: None,
                condition: None,
                skipped: None,
            })
        }

        TupleSource::JsonbFieldOwnership {
            table,
            identity_cols,
            column,
            path,
            relation,
        } => {
            let field_sql = render_jsonb_path(&quote_sql_identifier(column.as_str()), path)?;
            let field_operand = format!("({field_sql})");
            let subject_sql = typed_name_sql(&well_known.user, [field_operand.as_str()]);
            let (table_sql, object_sql, nameable) =
                owner_object_sql(owner_type, table, identity_cols, only_own_rows, names);
            let subject_guard =
                subject_fits_guard(&subject_sql, table, core::slice::from_ref(column), names);
            Some(TupleQuery {
                comment: format!(
                    "-- Jsonb field ownership ({column} -> {} references users)",
                    path.join(" -> ")
                ),
                sql: format!(
                    "SELECT {object_sql} AS object, '{relation}' AS relation, \
                     {subject_sql} AS subject\n\
                     FROM {table_sql}\n\
                     WHERE ({field_sql}) IS NOT NULL\n\
                     AND {nameable}{subject_guard};"
                ),
                description: None,
                condition: None,
                skipped: None,
            })
        }

        TupleSource::OwnerIdentity {
            owner_type: identity_type,
            principal_table,
            principal_identity_col,
            subject_type,
            relation,
        } => Some(render_ownership_tuple_source(
            ObjectSource {
                table: principal_table,
                type_name: identity_type,
                identity_cols: core::slice::from_ref(principal_identity_col),
                only_own_rows,
            },
            principal_identity_col,
            relation,
            subject_type,
            format!("-- Owner identities that are rows of {principal_table}"),
            None,
            names,
        )),

        TupleSource::ExplicitGrants {
            owner_type: granted_type,
            grant_table,
            grant_role_col,
            grant_grantee_col,
            grant_resource_col,
            role_cases,
            user_principal,
            team_principal,
            team_type,
        } => {
            if role_cases.is_empty() {
                return None;
            }
            let grant_table_sql = grant_table.sql_name();
            let grant_role_col_sql = quote_sql_identifier(grant_role_col.as_str());
            let grant_grantee_col_sql = quote_sql_identifier(grant_grantee_col.as_str());
            let grant_resource_col_sql = quote_sql_identifier(grant_resource_col.as_str());

            let case_arms: Vec<String> = role_cases
                .iter()
                .map(|(level, grant_rel, _)| format!("    WHEN {level} THEN '{grant_rel}'"))
                .collect();

            let role_ids: Vec<String> = role_cases
                .iter()
                .map(|(level, _, _)| level.to_string())
                .collect();
            let comment_roles: Vec<String> = role_cases
                .iter()
                .map(|(level, _, original)| format!("{level}={original}"))
                .collect();

            let case_expr = format!(
                "CASE og.{grant_role_col_sql}\n{}\n  END",
                case_arms.join("\n")
            );

            let grantee_ref = format!("og.{grant_grantee_col_sql}");
            let user_subject_sql = typed_name_sql(&well_known.user, [grantee_ref.as_str()]);
            let team_subject_sql = team_type
                .as_ref()
                .map(|tt| typed_name_sql(tt, [grantee_ref.as_str()]));
            let owner_ref = format!("og.{grant_resource_col_sql}");
            let object_sql = typed_name_sql(granted_type, [owner_ref.as_str()]);
            let mut subject_joins: Vec<String> = Vec::new();
            let mut principal_filter: Option<String> = None;
            let subject_expr = match (
                user_principal.as_ref(),
                team_principal.as_ref().zip(team_subject_sql.as_ref()),
            ) {
                (Some(up), Some((tp, team_subject_sql))) => {
                    let user_tbl_sql = up.table.sql_name();
                    let user_pk_sql = quote_sql_identifier(up.identity_col.as_str());
                    let team_tbl_sql = tp.table.sql_name();
                    let team_pk_sql = quote_sql_identifier(tp.identity_col.as_str());
                    subject_joins.push(format!(
                        "LEFT JOIN {user_tbl_sql} u ON u.{user_pk_sql} = og.{grant_grantee_col_sql}"
                    ));
                    subject_joins.push(format!(
                        "LEFT JOIN {team_tbl_sql} t ON t.{team_pk_sql} = og.{grant_grantee_col_sql}"
                    ));
                    principal_filter = Some(format!(
                        "(u.{user_pk_sql} IS NOT NULL OR t.{team_pk_sql} IS NOT NULL)"
                    ));
                    format!(
                        "CASE\n\
                         \x20   WHEN u.{user_pk_sql} IS NOT NULL THEN {user_subject_sql}\n\
                         \x20   WHEN t.{team_pk_sql} IS NOT NULL THEN {team_subject_sql}\n\
                         \x20 END"
                    )
                }
                (Some(_), None) => user_subject_sql,
                (None, Some((tp, team_subject_sql))) => {
                    let team_tbl_sql = tp.table.sql_name();
                    let team_pk_sql = quote_sql_identifier(tp.identity_col.as_str());
                    subject_joins.push(format!(
                        "JOIN {team_tbl_sql} t ON t.{team_pk_sql} = og.{grant_grantee_col_sql}"
                    ));
                    team_subject_sql.clone()
                }
                (None, None) => {
                    // Fail closed: neither user nor team principal could be resolved.
                    return Some(skipped_query(&SkippedTuples::NoPrincipalTypeForGrants {
                        grant_table: grant_table.clone(),
                    }));
                }
            };

            let subject_join_sql = if subject_joins.is_empty() {
                String::new()
            } else {
                format!("{}\n", subject_joins.join("\n                 "))
            };
            let mut where_predicates = vec![format!(
                "og.{grant_role_col_sql} IN ({})",
                role_ids.join(", ")
            )];
            if let Some(filter) = principal_filter {
                where_predicates.push(filter);
            }

            Some(TupleQuery {
                comment: format!(
                    "-- Explicit grants over {granted_type} identities ({grant_role_col}: {})",
                    comment_roles.join(", ")
                ),
                sql: format!(
                    "SELECT\n\
                     \x20 {object_sql} AS object,\n\
                     \x20 {case_expr} AS relation,\n\
                     \x20 {subject_expr} AS subject\n\
                     FROM {grant_table_sql} og\n\
                     {subject_join_sql}\
                     WHERE {};",
                    where_predicates.join("\nAND ")
                ),
                description: None,
                condition: None,
                skipped: None,
            })
        }

        TupleSource::TeamMembership {
            membership_table,
            team_col,
            user_col,
            team_type,
        } => {
            let membership_table_sql = membership_table.sql_name();
            let team_col_sql = quote_sql_identifier(team_col.as_str());
            let user_col_sql = quote_sql_identifier(user_col.as_str());
            let object_sql = typed_name_sql(team_type, [team_col_sql.as_str()]);
            let subject_sql = typed_name_sql(&well_known.user, [user_col_sql.as_str()]);
            let team_guards = join_row_is_nameable(
                "",
                &object_sql,
                Some(&subject_sql),
                membership_table,
                core::slice::from_ref(team_col),
                core::slice::from_ref(user_col),
                names,
            );
            Some(TupleQuery {
                comment: "-- Team memberships".to_string(),
                sql: format!(
                    "SELECT {object_sql} AS object, 'member' AS relation, \
                     {subject_sql} AS subject\n\
                     FROM {membership_table_sql}\n\
                     WHERE {team_col_sql} IS NOT NULL\n\
                     AND {user_col_sql} IS NOT NULL{team_guards};"
                ),
                description: None,
                condition: None,
                skipped: None,
            })
        }

        TupleSource::ExistsMembership {
            join_table,
            fk_cols,
            user_col,
            parent_type,
            relation,
            extra_predicates,
            gate,
        } => {
            let join_table_sql = join_table.sql_name();
            let fk_parts = quoted_key_parts(fk_cols);
            let user_col_sql = quote_sql_identifier(user_col.as_str());
            // The extra predicate joins a conjunction of NULL guards, so it is
            // parenthesised: a disjunction would otherwise break out of the AND.
            let null_guards = fk_parts
                .iter()
                .map(|part| format!("{part} IS NOT NULL"))
                .chain([format!("{user_col_sql} IS NOT NULL")])
                .collect::<Vec<_>>()
                .join(" AND ");
            let object_sql = typed_name_sql(parent_type, fk_parts.iter().map(String::as_str));
            let subject_sql = typed_name_sql(&well_known.user, [user_col_sql.as_str()]);
            let null_guards = join_row_is_nameable(
                &null_guards,
                &object_sql,
                Some(&subject_sql),
                join_table,
                fk_cols,
                core::slice::from_ref(user_col),
                names,
            );
            let Some(gate) = gate else {
                let where_clause = extra_predicates.sql().map_or_else(
                    || format!("\nWHERE {null_guards}"),
                    |e| format!("\nWHERE {null_guards}\nAND ({e})"),
                );
                return Some(TupleQuery {
                    comment: format!("-- {parent_type} membership from {join_table}"),
                    sql: format!(
                        "SELECT {object_sql} AS object, '{relation}' AS relation, \
                         {subject_sql} AS subject\n\
                         FROM {join_table_sql}{where_clause};"
                    ),
                    description: None,
                    condition: None,
                    skipped: None,
                });
            };
            // The clock rides the member tuple as a condition, so the query drops its
            // comparison and carries each column the check reads it against. When several
            // rows can key the same (object, user) it groups by that key and carries the
            // latest deadline, since MAX(deadline) is unpassed exactly when some row is.
            let (context, where_clause) = gate_context_sql(
                gate,
                &null_guards,
                extra_predicates
                    .sql_excluding_requests()
                    .into_iter()
                    .collect(),
            );
            let group_by = if gate.aggregate {
                format!("\nGROUP BY {}, {user_col_sql}", fk_parts.join(", "))
            } else {
                String::new()
            };
            Some(TupleQuery {
                comment: format!(
                    "-- {parent_type} membership from {join_table}, evaluated by condition {}",
                    gate.condition
                ),
                sql: format!(
                    "SELECT {object_sql} AS object, '{relation}' AS relation, \
                     {subject_sql} AS subject,\n\
                     \x20 '{}' AS condition, jsonb_build_object({context}) AS context\n\
                     FROM {join_table_sql}{where_clause}{group_by};",
                    gate.condition
                ),
                description: None,
                condition: Some(gate.condition.clone()),
                skipped: None,
            })
        }

        // Each share row is its own object, keyed on the join table's own primary key, so
        // two viewers of one guarded row become two objects rather than colliding on one.
        TupleSource::CallerSetShareGate {
            join_table,
            identity_cols,
            share_type,
            member_col,
            relation,
            condition,
            row_parameter,
            extra_predicates,
            temporal_context,
            ..
        } => {
            let join_table_sql = join_table.sql_name();
            let member_col_sql = quote_sql_identifier(member_col.as_str());
            let parameter_sql = quote_sql_string_literal(row_parameter);
            let identity_parts = quoted_key_parts(identity_cols);
            let object_sql = typed_name_sql(share_type, identity_parts.iter().map(String::as_str));
            let mut null_cols = identity_parts;
            if !identity_cols.contains(member_col) {
                null_cols.push(member_col_sql.clone());
            }
            let null_guards = null_cols
                .iter()
                .map(|part| format!("{part} IS NOT NULL"))
                .collect::<Vec<_>>()
                .join(" AND ");
            let null_guards = join_row_is_nameable(
                &null_guards,
                &object_sql,
                None,
                join_table,
                identity_cols,
                &[],
                names,
            );
            // The member the set compares, plus every column a clock comparison carries.
            let mut context = format!("{parameter_sql}, {member_col_sql}::text");
            for gate in temporal_context {
                let column_sql = quote_sql_identifier(gate.column.as_str());
                let key_sql = quote_sql_string_literal(&gate.parameter);
                let _ = write!(context, ", {key_sql}, {column_sql}");
            }
            // The clock's own comparison moved into the condition, so only what remains
            // filters, and each carried column must be present for the context to be read.
            let residual = if temporal_context.is_empty() {
                extra_predicates.sql()
            } else {
                let mut clauses: Vec<String> = extra_predicates
                    .sql_excluding_requests()
                    .into_iter()
                    .collect();
                for gate in temporal_context {
                    clauses.push(format!(
                        "{} IS NOT NULL",
                        quote_sql_identifier(gate.column.as_str())
                    ));
                }
                (!clauses.is_empty()).then(|| clauses.join(" AND "))
            };
            let where_clause = residual.map_or_else(
                || format!("\nWHERE {null_guards}"),
                |e| format!("\nWHERE {null_guards}\nAND ({e})"),
            );
            Some(TupleQuery {
                comment: format!(
                    "-- Caller-set share on {share_type} carrying {join_table}.{member_col}, \
                     evaluated by condition {condition}"
                ),
                sql: format!(
                    "SELECT {object_sql} AS object, '{relation}' AS relation, \
                     {wildcard_subject} AS subject,\n\
                     \x20 '{condition}' AS condition, \
                     jsonb_build_object({context}) AS context\n\
                     FROM {join_table_sql}{where_clause};"
                ),
                description: None,
                condition: Some(condition.clone()),
                skipped: None,
            })
        }

        // Each share row links its guarded object to its own share object, so a caller a
        // share admits reaches the guarded row through the share.
        TupleSource::ShareBridge {
            join_table,
            identity_cols,
            object_cols,
            guarded_type,
            share_type,
            relation,
        } => {
            let join_table_sql = join_table.sql_name();
            let object_parts = quoted_key_parts(object_cols);
            let identity_parts = quoted_key_parts(identity_cols);
            let object_sql = typed_name_sql(guarded_type, object_parts.iter().map(String::as_str));
            let subject_sql = typed_name_sql(share_type, identity_parts.iter().map(String::as_str));
            let mut base = object_parts
                .iter()
                .map(|part| format!("{part} IS NOT NULL"))
                .collect::<Vec<_>>()
                .join("\nAND ");
            for (col, part) in identity_cols.iter().zip(&identity_parts) {
                if !object_cols.contains(col) {
                    let _ = write!(base, "\nAND {part} IS NOT NULL");
                }
            }
            let guards = join_row_is_nameable(
                &base,
                &object_sql,
                Some(&subject_sql),
                join_table,
                object_cols,
                identity_cols,
                names,
            );
            Some(TupleQuery {
                comment: format!("-- {guarded_type} to {share_type} bridge for tuple-to-userset"),
                sql: format!(
                    "SELECT {object_sql} AS object, '{relation}' AS relation, \
                     {subject_sql} AS subject\n\
                     FROM {join_table_sql}\n\
                     WHERE {guards};"
                ),
                description: None,
                condition: None,
                skipped: None,
            })
        }

        TupleSource::ClosureBridge {
            link_table,
            object_cols,
            subject_cols,
            guarded_type,
            owner_type,
            relation,
            extra_predicates,
        } => {
            let link_table_sql = link_table.sql_name();
            let object_parts = quoted_key_parts(object_cols);
            let subject_parts = quoted_key_parts(subject_cols);
            let object_sql = typed_name_sql(guarded_type, object_parts.iter().map(String::as_str));
            let subject_sql = typed_name_sql(owner_type, subject_parts.iter().map(String::as_str));
            let mut base = object_parts
                .iter()
                .map(|part| format!("{part} IS NOT NULL"))
                .collect::<Vec<_>>()
                .join("\nAND ");
            for part in &subject_parts {
                let _ = write!(base, "\nAND {part} IS NOT NULL");
            }
            let guards = join_row_is_nameable(
                &base,
                &object_sql,
                Some(&subject_sql),
                link_table,
                object_cols,
                subject_cols,
                names,
            );
            let where_clause = extra_predicates.sql().map_or_else(
                || format!("\nWHERE {guards}"),
                |e| format!("\nWHERE {guards}\nAND ({e})"),
            );
            Some(TupleQuery {
                comment: format!(
                    "-- {guarded_type} to {owner_type} closure link from {link_table}"
                ),
                sql: format!(
                    "SELECT {object_sql} AS object, '{relation}' AS relation, \
                     {subject_sql} AS subject\n\
                     FROM {link_table_sql}{where_clause};"
                ),
                description: None,
                condition: None,
                skipped: None,
            })
        }

        // One tuple per membership row, keyed on the row's own identity, so the
        // condition is evaluated per row exactly as `EXISTS` is: no aggregation.
        TupleSource::MembershipShareMembers {
            join_table,
            identity_cols,
            user_col,
            share_type,
            relation,
            condition,
            extra_predicates,
            context,
        } => {
            let join_table_sql = join_table.sql_name();
            let identity_parts = quoted_key_parts(identity_cols);
            let user_col_sql = quote_sql_identifier(user_col.as_str());
            let object_sql = typed_name_sql(share_type, identity_parts.iter().map(String::as_str));
            let subject_sql = typed_name_sql(&well_known.user, [user_col_sql.as_str()]);
            let base = identity_parts
                .iter()
                .map(|part| format!("{part} IS NOT NULL"))
                .chain([format!("{user_col_sql} IS NOT NULL")])
                .collect::<Vec<_>>()
                .join(" AND ");
            let guards = join_row_is_nameable(
                &base,
                &object_sql,
                Some(&subject_sql),
                join_table,
                identity_cols,
                core::slice::from_ref(user_col),
                names,
            );
            let mut context_sql = String::new();
            let mut clauses: Vec<String> = extra_predicates
                .sql_excluding_requests()
                .into_iter()
                .collect();
            for (index, column) in context.iter().enumerate() {
                let column_sql = quote_sql_identifier(column.column.as_str());
                let key_sql = quote_sql_string_literal(&column.parameter);
                if index > 0 {
                    context_sql.push_str(", ");
                }
                let _ = write!(context_sql, "{key_sql}, {column_sql}");
                clauses.push(format!("{column_sql} IS NOT NULL"));
            }
            let where_clause = if clauses.is_empty() {
                format!("\nWHERE {guards}")
            } else {
                format!("\nWHERE {guards}\nAND ({})", clauses.join(" AND "))
            };
            Some(TupleQuery {
                comment: format!(
                    "-- Each row of {join_table} as its own {share_type} witness, \
                     evaluated by condition {condition}"
                ),
                sql: format!(
                    "SELECT {object_sql} AS object, '{relation}' AS relation, \
                     {subject_sql} AS subject,\n\
                     \x20 '{condition}' AS condition, \
                     jsonb_build_object({context_sql}) AS context\n\
                     FROM {join_table_sql}{where_clause};"
                ),
                description: None,
                condition: Some(condition.clone()),
                skipped: None,
            })
        }

        TupleSource::HolderMembers {
            holder_type,
            member_table,
            user_col,
            relation,
            extra_predicates,
            gate,
        } => {
            let member_table_sql = member_table.sql_name();
            let user_col_sql = quote_sql_identifier(user_col.as_str());
            let object_sql = typed_name_literal(holder_type, HOLDER_OBJECT_ID);
            let subject_sql = typed_name_sql(&well_known.user, [user_col_sql.as_str()]);
            let user_col_sql_guard = subject_fits_guard(
                &subject_sql,
                member_table,
                core::slice::from_ref(user_col),
                names,
            );
            let null_guards = format!("{user_col_sql} IS NOT NULL{user_col_sql_guard}");
            // DISTINCT because the holder is one object: two membership rows for the same
            // user would otherwise write the same tuple twice.
            let Some(gate) = gate else {
                let where_clause = extra_predicates.sql().map_or_else(
                    || format!("\nWHERE {null_guards}"),
                    |e| format!("\nWHERE {null_guards}\nAND ({e})"),
                );
                return Some(TupleQuery {
                    comment: format!("-- Everyone listed in {member_table}, held by {holder_type}"),
                    sql: format!(
                        "SELECT DISTINCT {object_sql} AS object, \
                         '{relation}' AS relation, {subject_sql} AS subject\n\
                         FROM {member_table_sql}{where_clause};"
                    ),
                    description: None,
                    condition: None,
                    skipped: None,
                });
            };
            let (context, where_clause) = gate_context_sql(
                gate,
                &null_guards,
                extra_predicates
                    .sql_excluding_requests()
                    .into_iter()
                    .collect(),
            );
            // Grouping by the user collapses several deadlines to their latest, which the
            // one holder object needs. Where the row already keys the user, DISTINCT is
            // enough and the row alone decides the record.
            let (distinct, group_by) = if gate.aggregate {
                ("", format!("\nGROUP BY {user_col_sql}"))
            } else {
                ("DISTINCT ", String::new())
            };
            Some(TupleQuery {
                comment: format!(
                    "-- Everyone listed in {member_table}, held by {holder_type}, \
                     evaluated by condition {}",
                    gate.condition
                ),
                sql: format!(
                    "SELECT {distinct}{object_sql} AS object, '{relation}' AS relation, \
                     {subject_sql} AS subject,\n\
                     \x20 '{}' AS condition, jsonb_build_object({context}) AS context\n\
                     FROM {member_table_sql}{where_clause}{group_by};",
                    gate.condition
                ),
                description: None,
                condition: Some(gate.condition.clone()),
                skipped: None,
            })
        }

        TupleSource::HolderBridge {
            table,
            identity_cols,
            relation,
            holder_type,
        } => {
            let (table_sql, object_sql, key_not_null) =
                owner_object_sql(owner_type, table, identity_cols, only_own_rows, names);
            let subject_sql = typed_name_literal(holder_type, HOLDER_OBJECT_ID);
            Some(TupleQuery {
                comment: format!("-- Every {table} row points at the {holder_type} holder"),
                sql: format!(
                    "SELECT {object_sql} AS object, '{relation}' AS relation, \
                     {subject_sql} AS subject\n\
                     FROM {table_sql}\n\
                     WHERE {key_not_null};"
                ),
                description: None,
                condition: None,
                skipped: None,
            })
        }

        // One link per membership row, so the holder resolves each row's witness.
        TupleSource::HolderShares {
            member_table,
            identity_cols,
            holder_type,
            share_type,
            relation,
        } => {
            let member_table_sql = member_table.sql_name();
            let identity_parts = quoted_key_parts(identity_cols);
            let object_sql = typed_name_literal(holder_type, HOLDER_OBJECT_ID);
            let subject_sql = typed_name_sql(share_type, identity_parts.iter().map(String::as_str));
            let base = identity_parts
                .iter()
                .map(|part| format!("{part} IS NOT NULL"))
                .collect::<Vec<_>>()
                .join(" AND ");
            let guards = join_row_is_nameable(
                &base,
                &object_sql,
                Some(&subject_sql),
                member_table,
                &[],
                identity_cols,
                names,
            );
            Some(TupleQuery {
                comment: format!(
                    "-- The {holder_type} holder links each {member_table} row's witness"
                ),
                sql: format!(
                    "SELECT {object_sql} AS object, '{relation}' AS relation, \
                     {subject_sql} AS subject\n\
                     FROM {member_table_sql}\n\
                     WHERE {guards};"
                ),
                description: None,
                condition: None,
                skipped: None,
            })
        }

        TupleSource::ParentBridge {
            table,
            fk_cols,
            parent_type,
            relation,
        } => {
            let Some((object_cols, parent_ref_cols)) = resolve_bridge_columns(table, fk_cols, db)
            else {
                let missing = fk_cols
                    .iter()
                    .find(|col| !table_id_has_column(db, table, col.as_str()))
                    .or_else(|| fk_cols.first())?;
                return Some(skipped_query(&SkippedTuples::BridgeColumnMissing {
                    table: table.clone(),
                    parent_type: parent_type.clone(),
                    fk_col: missing.clone(),
                }));
            };
            let table_sql = owner_table_reference(table, only_own_rows);
            let object_parts = quoted_key_parts(&object_cols);
            let parent_ref_parts = quoted_key_parts(&parent_ref_cols);
            let object_sql = typed_name_sql(owner_type, object_parts.iter().map(String::as_str));
            let subject_sql =
                typed_name_sql(parent_type, parent_ref_parts.iter().map(String::as_str));
            let bridge_guards = join_row_is_nameable(
                "",
                &object_sql,
                Some(&subject_sql),
                table,
                &object_cols,
                &parent_ref_cols,
                names,
            );
            let object_not_null = object_parts
                .iter()
                .map(|part| format!("{part} IS NOT NULL"))
                .collect::<Vec<_>>()
                .join("\nAND ");
            let parent_not_null = parent_ref_parts
                .iter()
                .map(|part| format!("{part} IS NOT NULL"))
                .collect::<Vec<_>>()
                .join("\nAND ");
            Some(TupleQuery {
                comment: format!("-- {table} to {parent_type} bridge for tuple-to-userset"),
                sql: format!(
                    "SELECT {object_sql} AS object, \
                     '{relation}' AS relation, \
                     {subject_sql} AS subject\n\
                     FROM {table_sql}\n\
                     WHERE {object_not_null}\n\
                     AND {parent_not_null}{bridge_guards};"
                ),
                description: None,
                condition: None,
                skipped: None,
            })
        }

        TupleSource::PublicFlag {
            table,
            identity_cols,
            flag_col,
            relation,
        } => {
            let (table_sql, object_sql, key_not_null) =
                owner_object_sql(owner_type, table, identity_cols, only_own_rows, names);
            let flag_col_sql = quote_sql_identifier(flag_col.as_str());
            Some(TupleQuery {
                comment: format!("-- Public access flag ({flag_col})"),
                sql: format!(
                    "SELECT {object_sql} AS object, '{relation}' AS relation, \
                     {wildcard_subject} AS subject\n\
                     FROM {table_sql}\n\
                     WHERE {key_not_null}\n\
                     AND {flag_col_sql} = TRUE;"
                ),
                description: None,
                condition: None,
                skipped: None,
            })
        }

        TupleSource::RowPresenceGate {
            table,
            identity_cols,
            relation,
            columns,
        } => {
            let (table_sql, object_sql, key_not_null) =
                owner_object_sql(owner_type, table, identity_cols, only_own_rows, names);
            let presence = columns
                .iter()
                .map(|column| format!("{} IS NOT NULL", quote_sql_identifier(column.as_str())))
                .collect::<Vec<_>>()
                .join("\nAND ");
            Some(TupleQuery {
                comment: format!("-- Strict function argument presence ({presence})"),
                sql: format!(
                    "SELECT {object_sql} AS object, '{relation}' AS relation, \
                     {wildcard_subject} AS subject\n\
                     FROM {table_sql}\n\
                     WHERE {key_not_null}\n\
                     AND {presence};"
                ),
                description: None,
                condition: None,
                skipped: None,
            })
        }

        TupleSource::AttributeGate {
            table,
            identity_cols,
            predicate,
            relation,
        } => {
            let (table_sql, object_sql, key_not_null) =
                owner_object_sql(owner_type, table, identity_cols, only_own_rows, names);
            let column_sql = quote_sql_identifier(predicate.column.as_str());
            let test_sql = render_attribute_test(&predicate.test)?;
            Some(TupleQuery {
                comment: format!("-- Attribute gate ({} {test_sql})", predicate.column),
                sql: format!(
                    "SELECT {object_sql} AS object, '{relation}' AS relation, \
                     {wildcard_subject} AS subject\n\
                     FROM {table_sql}\n\
                     WHERE {key_not_null}\n\
                     AND {column_sql} {test_sql};"
                ),
                description: None,
                condition: None,
                skipped: None,
            })
        }

        // Five columns, not three: the loader needs the condition name and the context
        // the row supplies, since the service cannot know either from the tuple alone.
        TupleSource::ConditionalAttributeGate {
            table,
            identity_cols,
            relation,
            condition,
            row_parameter,
            column,
        } => {
            let (table_sql, object_sql, key_not_null) =
                owner_object_sql(owner_type, table, identity_cols, only_own_rows, names);
            let column_sql = quote_sql_identifier(column.as_str());
            let parameter_sql = quote_sql_string_literal(row_parameter);
            Some(TupleQuery {
                comment: format!(
                    "-- Request-time gate on {column}, evaluated by condition {condition}"
                ),
                sql: format!(
                    "SELECT {object_sql} AS object, '{relation}' AS relation, \
                     {wildcard_subject} AS subject,\n\
                     \x20 '{condition}' AS condition, \
                     jsonb_build_object({parameter_sql}, {column_sql}) AS context\n\
                     FROM {table_sql}\n\
                     WHERE {key_not_null}\n\
                     AND {column_sql} IS NOT NULL;"
                ),
                description: None,
                condition: Some(condition.clone()),
                skipped: None,
            })
        }

        TupleSource::SessionAttributeGate {
            table,
            identity_cols,
            relation,
            condition,
            row_parameter,
            column,
            ..
        } => {
            let (table_sql, object_sql, key_not_null) =
                owner_object_sql(owner_type, table, identity_cols, only_own_rows, names);
            let parameter_sql = quote_sql_string_literal(row_parameter);
            let column_sql = quote_sql_identifier(column.as_str());
            // A NULL row value matches nothing in PostgreSQL, so it needs no tuple.
            Some(TupleQuery {
                comment: format!(
                    "-- Request-scoped gate carrying the row's {column}, evaluated by \
                     condition {condition}"
                ),
                sql: format!(
                    "SELECT {object_sql} AS object, '{relation}' AS relation, \
                     {wildcard_subject} AS subject,\n\
                     \x20 '{condition}' AS condition, \
                     jsonb_build_object({parameter_sql}, {column_sql}::text) AS context\n\
                     FROM {table_sql}\n\
                     WHERE {key_not_null}\n\
                     AND {column_sql} IS NOT NULL;"
                ),
                description: None,
                condition: Some(condition.clone()),
                skipped: None,
            })
        }

        // The constant a gate tests is a fact about the policy, so the query has no `FROM`
        // and yields its one row whatever any table holds.
        TupleSource::RequestGateEntry {
            gate_type,
            gate_object,
            relation,
            condition,
            row_parameter,
            atom,
        } => {
            let object_sql = typed_name_literal(gate_type, gate_object);
            let parameter_sql = quote_sql_string_literal(row_parameter);
            let value_sql = quote_sql_string_literal(&atom.value);
            Some(TupleQuery {
                comment: format!(
                    "-- Gate {gate_object} tests the constant {}, which the policy decides \
                     rather than any row, evaluated by condition {condition}",
                    atom.value
                ),
                sql: format!(
                    "SELECT {object_sql} AS object, '{relation}' AS relation, \
                     {wildcard_subject} AS subject,\n\
                     \x20 '{condition}' AS condition, \
                     jsonb_build_object({parameter_sql}, {value_sql}) AS context;"
                ),
                description: None,
                condition: Some(condition.clone()),
                skipped: None,
            })
        }

        TupleSource::ConstantTrue {
            table,
            identity_cols,
            relation,
        } => {
            let (table_sql, object_sql, key_not_null) =
                owner_object_sql(owner_type, table, identity_cols, only_own_rows, names);
            Some(TupleQuery {
                comment: "-- Constant TRUE policy (all rows are visible)".to_string(),
                sql: format!(
                    "SELECT {object_sql} AS object, '{relation}' AS relation, \
                     {wildcard_subject} AS subject\n\
                     FROM {table_sql}\n\
                     WHERE {key_not_null};"
                ),
                description: None,
                condition: None,
                skipped: None,
            })
        }

        TupleSource::PolicyScope {
            table,
            identity_cols,
            scope_relation,
            scope_type,
            scope_object,
        } => {
            let (table_sql, object_sql, key_not_null) =
                owner_object_sql(owner_type, table, identity_cols, only_own_rows, names);
            let subject_sql = typed_name_literal(scope_type, scope_object);
            Some(TupleQuery {
                comment: format!("-- Every {table} row is judged by the scope {scope_object}"),
                sql: format!(
                    "SELECT {object_sql} AS object, \
                     '{scope_relation}' AS relation, \
                     {subject_sql} AS subject\n\
                     FROM {table_sql}\n\
                     WHERE {key_not_null};"
                ),
                description: None,
                condition: None,
                skipped: None,
            })
        }

        // No `FROM`: which roles a scope admits is a fact about the policy, so the query
        // yields its one row whatever any table holds, and the load no longer scans a
        // table per role to find out.
        TupleSource::PolicyScopeRoles {
            scope_type,
            scope_object,
            relation,
            pg_role,
        } => {
            let object_sql = typed_name_literal(scope_type, scope_object);
            let subject_sql = typed_name_literal(&well_known.pg_role, pg_role);
            Some(TupleQuery {
                comment: format!(
                    "-- Scope {scope_object} admits PostgreSQL role '{pg_role}', which the \
                     policy decides rather than any row"
                ),
                sql: format!(
                    "SELECT {object_sql} AS object, \
                     '{relation}' AS relation, \
                     {subject_sql} AS subject;"
                ),
                description: None,
                condition: None,
                skipped: None,
            })
        }

        TupleSource::Skipped { reason } => Some(skipped_query(reason)),
    }
}

/// The two comment lines that stand where a tuple query could not be built.
fn skipped_query(reason: &SkippedTuples) -> TupleQuery {
    sanitize_tuple_query(TupleQuery {
        comment: reason.comment(),
        sql: reason.body(),
        description: None,
        condition: None,
        skipped: Some(reason.clone()),
    })
}

/// The columns naming the bridge's two ends: every column identifying a row of `table`,
/// and the ones whose values name the parent.
///
/// The parent-side columns have to be columns of `table`, since the policy compares
/// them against the membership row. A name the schema does not carry is a bridge
/// nobody can write.
pub(crate) fn resolve_bridge_columns<DB: DatabaseLike>(
    table: &TableId,
    fk_cols: &[ColumnName],
    db: &DB,
) -> Option<(Vec<ColumnName>, Vec<ColumnName>)> {
    let object_cols = resolve_row_identity(table, db)?;
    fk_cols
        .iter()
        .all(|col| table_id_has_column(db, table, col.as_str()))
        .then(|| (object_cols, fk_cols.to_vec()))
}

/// The `FROM` reference for a query minting this type's objects.
///
/// `ONLY` keeps inheritance children's rows out, since the parent's key does not
/// span them and a shared key value would merge two rows into one object.
fn owner_table_reference(table: &TableId, only_own_rows: bool) -> String {
    let quoted = table.sql_name();
    if only_own_rows {
        format!("ONLY {quoted}")
    } else {
        quoted
    }
}
/// Quote one stored identifier as one SQL identifier.
pub(crate) fn quote_sql_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

/// Quote `value` as a SQL string literal.
///
/// With `standard_conforming_strings` on, which `PostgreSQL` has defaulted to since 9.1,
/// a backslash is an ordinary character and doubling the quote is the whole escape.
fn quote_sql_string_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// SQL spelling of what an attribute guard asks of its column, after the column.
pub(crate) fn render_attribute_test(test: &AttributeTest) -> Option<String> {
    match test {
        AttributeTest::Compare { operator, value } => Some(format!(
            "{} {}",
            operator.sql(),
            render_attribute_literal(value)?
        )),
        AttributeTest::In(values) if !values.is_empty() => {
            let rendered = values
                .iter()
                .map(render_attribute_literal)
                .collect::<Option<Vec<_>>>()?;
            Some(format!("IN ({})", rendered.join(", ")))
        }
        AttributeTest::In(_) => None,
    }
}

/// SQL spelling of the literal an attribute guard compares against.
///
/// A number keeps its source spelling, so `priority >= 3` compares against `3` rather
/// than a reformatted value, and the column's own type decides the comparison.
fn render_attribute_literal(value: &AttributeLiteral) -> Option<String> {
    match value {
        AttributeLiteral::Text(text) => Some(quote_sql_string_literal(text)),
        AttributeLiteral::Number(number) => Some(number.clone()),
        AttributeLiteral::Boolean(flag) => Some(if *flag { "TRUE" } else { "FALSE" }.to_string()),
        _ => None,
    }
}

/// Render a jsonb key chain as an extraction expression on `column_sql`, the last hop
/// as `->>` so the result is text rather than a quoted JSON string.
fn render_jsonb_path(column_sql: &str, path: &[String]) -> Option<String> {
    let (last, leading) = path.split_last()?;
    let mut out = column_sql.to_string();
    for key in leading {
        out.push_str(" -> ");
        out.push_str(&quote_sql_string_literal(key));
    }
    out.push_str(" ->> ");
    out.push_str(&quote_sql_string_literal(last));
    Some(out)
}

/// The condition-context argument string and the `WHERE` clause a gate's columns require.
fn gate_context_sql(
    gate: &MembershipGate,
    null_guards: &str,
    extra: Vec<String>,
) -> (String, String) {
    let mut context = String::new();
    let mut clauses = extra;
    for (index, column) in gate.context.iter().enumerate() {
        let column_sql = quote_sql_identifier(column.column.as_str());
        let key_sql = quote_sql_string_literal(&column.parameter);
        clauses.push(format!("{column_sql} IS NOT NULL"));
        let carried = if gate.aggregate {
            match column.witness {
                ContextWitness::Latest => format!("MAX({column_sql})"),
                ContextWitness::Earliest => format!("MIN({column_sql})"),
            }
        } else {
            column_sql
        };
        if index > 0 {
            context.push_str(", ");
        }
        let _ = write!(context, "{key_sql}, {carried}");
    }
    let where_clause = if clauses.is_empty() {
        format!("\nWHERE {null_guards}")
    } else {
        format!("\nWHERE {null_guards}\nAND ({})", clauses.join(" AND "))
    };
    (context, where_clause)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::function_registry::FunctionRegistry;
    use crate::classifier::patterns::{
        BooleanFlag, ClassifiedPolicy, ConfidenceLevel, DirectOwnership,
    };
    use crate::generator::model_generator::GeneratorSettings;
    use crate::parser::names::role_scope_name;

    fn table(name: &str) -> TableId {
        TableId::from_stored(None, name.to_string())
    }
    use crate::parser::sql_parser::{parse_schema, DatabaseLike};
    use crate::translator::Translation;

    fn plan_queries<DB: DatabaseLike>(db: &DB, registry: &FunctionRegistry) -> Vec<TupleQuery> {
        let classified = crate::classifier::policy_classifier::classify_policies(db, registry);
        Translation::plan(
            classified,
            db,
            registry,
            ConfidenceLevel::D,
            &GeneratorSettings::default(),
        )
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .tuple_queries()
        .to_vec()
    }

    #[test]
    fn an_empty_list_renders_no_sql() {
        assert_eq!(render_attribute_test(&AttributeTest::In(Vec::new())), None);
    }

    fn role_threshold_registry() -> FunctionRegistry {
        let mut registry = FunctionRegistry::new();
        registry
            .load_from_json(
                r#"{
  "role_level": {
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {"viewer": 1, "editor": 2},
    "grant_table": "object_grants",
    "grant_grantee_col": "grantee_id",
    "grant_resource_col": "resource_id",
    "grant_role_col": "role_level"
  },
  "auth_current_user_id": {
    "kind": "current_user_accessor",
    "returns": "uuid"
  }
}"#,
            )
            .expect("registry json should parse");
        registry
    }

    fn render_explicit_grants(
        source: &TupleSource,
        owner_type: &TypeName,
        well_known: &WellKnownTypes,
    ) -> TupleQuery {
        let db = parse_schema("CREATE TABLE docs(id uuid primary key);").expect("parse");
        let bounds = UnboundedColumns::resolve(&db);
        render_tuple_source(
            source,
            owner_type,
            false,
            well_known,
            NameContext::new(&bounds),
            &db,
        )
        .expect("should produce a query")
    }

    #[test]
    fn rendered_source_key_scopes_only_owner_type_objects() {
        let shared = TupleSource::TeamMembership {
            membership_table: table("team_members"),
            team_col: ColumnName::from_stored("team_id"),
            user_col: ColumnName::from_stored("user_id"),
            team_type: TypeName::canonicalized("team"),
        };
        assert_eq!(
            rendered_source_key(&shared, &TypeName::canonicalized("docs"), false),
            rendered_source_key(&shared, &TypeName::canonicalized("memos"), true)
        );

        let owned = TupleSource::DirectOwnership {
            table: table("docs"),
            identity_cols: vec![ColumnName::from_stored("id")],
            owner_col: ColumnName::from_stored("owner_id"),
            relation: RelationName::canonicalized("owner"),
        };
        assert_ne!(
            rendered_source_key(&owned, &TypeName::canonicalized("docs"), false),
            rendered_source_key(&owned, &TypeName::canonicalized("memos"), false)
        );
        assert_ne!(
            rendered_source_key(&owned, &TypeName::canonicalized("docs"), false),
            rendered_source_key(&owned, &TypeName::canonicalized("docs"), true)
        );
    }

    #[test]
    fn format_tuples_ends_with_exactly_one_newline() {
        let tuples = vec![
            TupleQuery {
                comment: "-- one".to_string(),
                sql: "SELECT 1;".to_string(),
                description: None,
                condition: None,
                skipped: None,
            },
            TupleQuery {
                comment: "-- two".to_string(),
                sql: "SELECT 2;".to_string(),
                description: None,
                condition: None,
                skipped: None,
            },
        ];
        let formatted = format_tuples(&tuples);
        // Must end with exactly one newline after the last SQL statement.
        assert!(formatted.ends_with("SELECT 2;\n"));
        assert!(!formatted.ends_with("SELECT 2;\n\n"));
    }

    #[test]
    fn format_tuples_pins_session_output_settings() {
        let tuples = [TupleQuery {
            comment: "-- one".to_string(),
            sql: "SELECT 1;".to_string(),
            description: None,
            condition: None,
            skipped: None,
        }];

        assert!(format_tuples(&tuples).starts_with(
            "SET TIME ZONE 'UTC';\nSET DateStyle = 'ISO, MDY';\nSET bytea_output = 'hex';\n\n"
        ));
    }

    #[test]
    fn format_tuples_empty_input_returns_empty_string() {
        assert_eq!(format_tuples(&[]), String::new());
    }

    #[test]
    fn resolve_bridge_columns_covers_safe_and_skip_paths() {
        let db = parse_schema(
            r"
CREATE TABLE docs(id uuid primary key, project_id uuid);
CREATE TABLE links(resource_uuid uuid, project_uuid uuid);
CREATE TABLE projects(id uuid primary key);
CREATE TABLE status(status uuid primary key);
CREATE TABLE events(label text, event_uuid uuid primary key, project_id uuid);
CREATE TABLE categories(id uuid primary key);
CREATE TABLE 日本(id uuid primary key);
",
        )
        .expect("schema should parse");

        assert_eq!(
            resolve_bridge_columns(
                &table("missing"),
                &[ColumnName::from_stored("project_id")],
                &db
            ),
            None
        );
        assert_eq!(
            resolve_bridge_columns(
                &table("docs"),
                &[ColumnName::from_stored("project_id")],
                &db
            ),
            Some((
                vec![ColumnName::from_stored("id")],
                vec![ColumnName::from_stored("project_id")]
            ))
        );
        // A column the table does not carry is a bridge nobody writes, whatever the name
        // suggests about the parent.
        assert_eq!(
            resolve_bridge_columns(
                &table("projects"),
                &[ColumnName::from_stored("project_id")],
                &db
            ),
            None
        );
        assert_eq!(
            resolve_bridge_columns(
                &table("status"),
                &[ColumnName::from_stored("status_id")],
                &db
            ),
            None
        );
        assert_eq!(
            resolve_bridge_columns(
                &table("categories"),
                &[ColumnName::from_stored("category_id")],
                &db
            ),
            None
        );
        // Both names canonicalize to `resource`, which used to be enough to bridge one
        // table to another it has nothing to do with. The `id` case beside it keeps the
        // refusal from resting on an unparsed table.
        assert_eq!(
            resolve_bridge_columns(
                &table("\u{65e5}\u{672c}"),
                &[ColumnName::from_stored("\u{4e2d}\u{6587}")],
                &db
            ),
            None
        );
        assert_eq!(
            resolve_bridge_columns(
                &table("\u{65e5}\u{672c}"),
                &[ColumnName::from_stored("id")],
                &db
            ),
            Some((
                vec![ColumnName::from_stored("id")],
                vec![ColumnName::from_stored("id")]
            ))
        );
        assert_eq!(
            resolve_bridge_columns(
                &table("events"),
                &[ColumnName::from_stored("project_id")],
                &db
            ),
            Some((
                vec![ColumnName::from_stored("event_uuid")],
                vec![ColumnName::from_stored("project_id")]
            ))
        );
        // One present and one absent column: the absent one closes the bridge.
        assert_eq!(
            resolve_bridge_columns(
                &table("docs"),
                &[
                    ColumnName::from_stored("project_id"),
                    ColumnName::from_stored("absent")
                ],
                &db
            ),
            None
        );
        assert_eq!(
            resolve_bridge_columns(
                &table("links"),
                &[ColumnName::from_stored("project_id")],
                &db
            ),
            None
        );
    }

    #[test]
    fn generate_tuple_queries_reads_using_and_with_check() {
        let db = parse_schema(
            r"
CREATE TABLE public.docs(id uuid primary key, owner_id uuid, is_public boolean);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
-- FOR ALL so the USING clause also grants reads, without which nothing is reachable.
CREATE POLICY docs_update ON docs FOR ALL
  USING (owner_id = current_user)
  WITH CHECK (owner_id = current_user);
",
        )
        .expect("schema should parse");

        let policy = db.policies().next().expect("policy should exist");
        let mut classified = ClassifiedPolicy::from_policy(policy, &db);
        classified.using_classification = Some(ClassifiedExpr {
            pattern: PatternClass::P3DirectOwnership(DirectOwnership {
                column: ColumnName::from_stored("owner_id"),
            }),
            confidence: ConfidenceLevel::A,
        });
        classified.with_check_classification = Some(ClassifiedExpr {
            pattern: PatternClass::P6BooleanFlag(BooleanFlag {
                column: ColumnName::from_stored("is_public"),
                admits_null: false,
            }),
            confidence: ConfidenceLevel::A,
        });

        let outputs = Translation::plan(
            vec![classified],
            &db,
            &FunctionRegistry::new(),
            ConfidenceLevel::D,
            &GeneratorSettings::default(),
        )
        .expect("translation should plan")
        .outputs_accepting_gaps();
        let queries = outputs.tuple_queries();
        assert!(queries.iter().any(|q| q
            .comment
            .contains("User ownership (owner_id references users)")));
        assert!(queries
            .iter()
            .any(|q| q.comment.contains("Public access flag (is_public)")));
    }

    #[test]
    fn generate_tuple_queries_emit_policy_scope_tuples_for_non_public_roles() {
        let db = parse_schema(
            r"
CREATE TABLE public.docs(id uuid primary key, owner_id uuid);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT TO app_user, auditors
  USING (owner_id = current_user);
",
        )
        .expect("schema should parse");

        let queries = plan_queries(&db, &FunctionRegistry::new());
        let scope_relation =
            role_scope_name("usage", &["app_user".to_string(), "auditors".to_string()]);

        assert!(queries
            .iter()
            .any(|q| q.sql.contains(&format!("'{scope_relation}' AS relation"))));
        assert!(queries
            .iter()
            .any(|q| q.sql.contains("'pg_role:app_user' AS subject")));
        assert!(queries
            .iter()
            .any(|q| q.sql.contains("'pg_role:auditors' AS subject")));
    }

    #[test]
    fn generate_role_threshold_tuples_uses_policy_resource_column_for_grant_join() {
        let db = parse_schema(
            r"
CREATE TABLE public.users(id uuid primary key);
CREATE TABLE public.docs(id uuid primary key, owner_id uuid references users(id));
CREATE TABLE public.object_grants(grantee_id uuid, resource_id uuid, role_level integer);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
  USING (role_level(auth_current_user_id(), id) >= 2);
",
        )
        .expect("schema should parse");

        let registry = role_threshold_registry();
        let queries = plan_queries(&db, &registry);

        let pointer = queries
            .iter()
            .find(|q| q.comment.contains("docs to object_grants_owner bridge"))
            .expect("expected the pointer at the owner");
        assert!(
            pointer
                .sql
                .contains("'object_grants_owner:' || CASE WHEN \"id\""),
            "expected the row to point at the owner named by the policy's column `id`, got:\n{}",
            pointer.sql
        );
        let grants = queries
            .iter()
            .find(|q| {
                q.comment
                    .contains("Explicit grants over object_grants_owner")
            })
            .expect("expected explicit grants tuple query");
        assert!(
            !grants.sql.contains("JOIN \"docs\""),
            "a grant is a fact about the owner, so it reads no guarded table, got:\n{}",
            grants.sql
        );
    }

    #[test]
    fn generate_role_threshold_tuples_extracts_resource_column_from_composite_classification() {
        let db = parse_schema(
            r"
CREATE TABLE public.users(id uuid primary key);
CREATE TABLE public.docs(id uuid primary key, owner_id uuid references users(id), is_public boolean);
CREATE TABLE public.object_grants(grantee_id uuid, resource_id uuid, role_level integer);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
  USING ((role_level(auth_current_user_id(), id) >= 2) AND is_public = TRUE);
",
        )
        .expect("schema should parse");

        let registry = role_threshold_registry();
        let queries = plan_queries(&db, &registry);

        let pointer = queries
            .iter()
            .find(|q| q.comment.contains("docs to object_grants_owner bridge"))
            .expect("expected the pointer at the owner");
        assert!(
            pointer
                .sql
                .contains("'object_grants_owner:' || CASE WHEN \"id\""),
            "expected composite policy extraction to keep the pointer on `id`, got:\n{}",
            pointer.sql
        );
    }

    /// Two policies naming two owner columns each get their own pointer, because a grant is
    /// a fact about the value the call passed and the two calls passed different values.
    #[test]
    fn generate_role_threshold_tuples_points_at_every_owner_column() {
        let db = parse_schema(
            r"
CREATE TABLE public.users(id uuid primary key);
CREATE TABLE public.docs(id uuid primary key, owner_id uuid references users(id), project_id uuid);
CREATE TABLE public.object_grants(grantee_id uuid, resource_id uuid, role_level integer);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select_id ON docs FOR SELECT
  USING (role_level(auth_current_user_id(), id) >= 2);
CREATE POLICY docs_select_project ON docs FOR SELECT
  USING (role_level(auth_current_user_id(), project_id) >= 2);
",
        )
        .expect("schema should parse");

        let registry = role_threshold_registry();
        let queries = plan_queries(&db, &registry);

        let pointers: Vec<&str> = queries
            .iter()
            .filter(|q| q.comment.contains("docs to object_grants_owner bridge"))
            .map(|q| q.sql.as_str())
            .collect();
        assert_eq!(
            pointers.len(),
            2,
            "each owner column names its own pointer: {pointers:#?}"
        );
        assert!(
            pointers
                .iter()
                .any(|sql| sql.contains("'object_grants_owner:' || CASE WHEN \"id\"")),
            "the policy naming `id` points at the owner that value names: {pointers:#?}"
        );
        assert!(
            pointers
                .iter()
                .any(|sql| sql.contains("'object_grants_owner:' || CASE WHEN \"project_id\"")),
            "the policy naming `project_id` points at the owner that value names: {pointers:#?}"
        );
        assert!(
            queries.iter().any(|q| q
                .comment
                .contains("Explicit grants over object_grants_owner")),
            "the grants are facts about the owner, so two columns do not refuse them"
        );
    }

    /// The same, where one policy reaches two owner columns through an `OR`.
    #[test]
    fn generate_role_threshold_tuples_points_at_both_columns_of_one_policy() {
        let db = parse_schema(
            r"
CREATE TABLE public.users(id uuid primary key);
CREATE TABLE public.docs(id uuid primary key, owner_id uuid references users(id), project_id uuid);
CREATE TABLE public.object_grants(grantee_id uuid, resource_id uuid, role_level integer);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
  USING (
    (role_level(auth_current_user_id(), id) >= 2)
    OR (role_level(auth_current_user_id(), project_id) >= 2)
  );
",
        )
        .expect("schema should parse");

        let registry = role_threshold_registry();
        let queries = plan_queries(&db, &registry);

        let pointers: Vec<&str> = queries
            .iter()
            .filter(|q| q.comment.contains("docs to object_grants_owner bridge"))
            .map(|q| q.sql.as_str())
            .collect();
        assert_eq!(
            pointers.len(),
            2,
            "each arm of the OR points at the owner its own call named: {pointers:#?}"
        );
        assert!(
            queries.iter().any(|q| q
                .comment
                .contains("Explicit grants over object_grants_owner")),
            "the grants are facts about the owner, so two columns do not refuse them"
        );
    }

    #[test]
    fn aliased_p4_membership_tuples_do_not_leak_correlated_or_current_user_predicates() {
        let db = parse_schema(
            r"
CREATE TABLE public.docs(id uuid primary key);
CREATE TABLE public.doc_members(doc_id uuid, user_id uuid, role text);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT USING (
  EXISTS (
    SELECT 1
    FROM doc_members dm
    WHERE dm.doc_id = docs.id
      AND dm.user_id = current_user
      AND dm.role = 'admin'
  )
);
",
        )
        .expect("schema should parse");

        let queries = plan_queries(&db, &FunctionRegistry::new());

        let membership_query = queries
            .iter()
            .find(|q| q.comment.contains("membership from public.doc_members"))
            .expect("expected doc membership tuple query");

        assert!(
            membership_query.sql.contains("role = 'admin'"),
            "expected role filter to be preserved, got:\n{}",
            membership_query.sql
        );
        assert!(
            !membership_query.sql.contains("docs.id"),
            "correlated outer-table predicate must not leak into tuple SQL, got:\n{}",
            membership_query.sql
        );
        assert!(
            !membership_query.sql.contains("current_user"),
            "current_user predicate should be consumed as subject mapping, got:\n{}",
            membership_query.sql
        );
        assert!(
            !membership_query.sql.contains("dm."),
            "join-table alias should not leak into tuple SQL when FROM has no alias, got:\n{}",
            membership_query.sql
        );
    }

    #[test]
    fn canonical_table_name_is_used_for_tuple_object_prefixes() {
        let db = parse_schema(
            r"
CREATE SCHEMA app;
CREATE TABLE app.docs(id uuid primary key, owner_id uuid);
ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON app.docs USING (owner_id = current_user);
",
        )
        .expect("schema should parse");

        let queries = plan_queries(&db, &FunctionRegistry::new());

        let ownership_query = queries
            .iter()
            .find(|q| q.comment.contains("User ownership"))
            .expect("expected ownership tuple query");
        assert!(ownership_query.sql.contains("'docs:' ||"));
        assert!(!ownership_query.sql.contains("'app.docs:' ||"));
    }

    #[test]
    fn tuple_sql_quotes_identifiers_for_mixed_case_and_reserved_names() {
        let db = parse_schema(
            r#"
CREATE TABLE public."Doc Items"(
  id uuid primary key,
  "OwnerID" uuid
);
ALTER TABLE "Doc Items" ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON "Doc Items" FOR SELECT
  USING ("OwnerID" = current_user);
"#,
        )
        .expect("schema should parse");

        let queries = plan_queries(&db, &FunctionRegistry::new());

        let ownership_query = queries
            .iter()
            .find(|q| q.comment.contains("User ownership"))
            .expect("expected ownership tuple query");

        assert!(
            ownership_query
                .sql
                .contains(r#"THEN "OwnerID"::text ELSE '~' || encode(convert_to("OwnerID"::text"#),
            "subject column should be quoted everywhere the encoding reads it, got:\n{}",
            ownership_query.sql
        );
        assert!(
            ownership_query.sql.contains("END AS subject"),
            "the subject is the encoded value, not the raw column, got:\n{}",
            ownership_query.sql
        );
        assert!(
            ownership_query
                .sql
                .contains("FROM \"public\".\"Doc Items\""),
            "table name should be quoted, got:\n{}",
            ownership_query.sql
        );
    }

    #[test]
    fn tuple_generation_fails_closed_when_object_identifier_column_is_missing() {
        let db = parse_schema(
            r"
CREATE TABLE docs(doc_uuid uuid, owner_id uuid);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
  USING (owner_id = current_user);
",
        )
        .expect("schema should parse");

        let queries = plan_queries(&db, &FunctionRegistry::new());

        assert!(
            queries
                .iter()
                .any(|q| q.comment.contains("missing object identifier column")),
            "expected explicit TODO when object identifier column cannot be resolved"
        );
        assert!(
            !queries.iter().any(|q| q.comment.contains("User ownership")),
            "ownership tuples should not be emitted without a stable object identifier column"
        );
    }

    #[test]
    fn quote_sql_identifier_preserves_stored_names() {
        for name in ["simple", "null", "with", "join", "default", "case"] {
            assert_eq!(quote_sql_identifier(name), format!("\"{name}\""));
        }
        assert_eq!(quote_sql_identifier(""), "\"\"");
        assert_eq!(quote_sql_identifier(" spaced "), "\" spaced \"");
        assert_eq!(quote_sql_identifier("with\"quote"), "\"with\"\"quote\"");
        assert_eq!(quote_sql_identifier("\"quoted\""), "\"\"\"quoted\"\"\"");
    }

    #[test]
    fn explicit_grants_with_no_principal_tables_emits_todo_not_user_prefix() {
        use crate::generator::ir::TupleSource;
        // Build the IR directly and call render_tuple_source.
        // Both user_principal and team_principal are None → fail-closed path.
        let source = TupleSource::ExplicitGrants {
            owner_type: TypeName::canonicalized("doc_grants_owner"),
            grant_table: table("doc_grants"),
            grant_role_col: ColumnName::from_stored("role_level"),
            grant_grantee_col: ColumnName::from_stored("grantee_id"),
            grant_resource_col: ColumnName::from_stored("doc_id"),
            role_cases: vec![(
                1,
                RelationName::canonicalized("viewer"),
                "viewer".to_string(),
            )],
            user_principal: None,
            team_principal: None,
            team_type: None,
        };
        let query = render_explicit_grants(
            &source,
            &TypeName::canonicalized("docs"),
            &WellKnownTypes::default(),
        );
        assert!(
            query.comment.contains("TODO [Level C]"),
            "expected a TODO comment, got: {}",
            query.comment
        );
        assert!(
            query.comment.contains("doc_grants"),
            "TODO should mention the grant table, got: {}",
            query.comment
        );
        assert!(
            !query.sql.contains("'user:'"),
            "should not emit user: prefix when principal is unresolvable, got: {}",
            query.sql
        );
    }

    #[test]
    fn explicit_grants_team_only_does_not_fallback_to_user_prefix() {
        use crate::generator::ir::{PrincipalInfo, TupleSource};

        let source = TupleSource::ExplicitGrants {
            owner_type: TypeName::canonicalized("doc_grants_owner"),
            grant_table: table("doc_grants"),
            grant_role_col: ColumnName::from_stored("role_level"),
            grant_grantee_col: ColumnName::from_stored("grantee_id"),
            grant_resource_col: ColumnName::from_stored("doc_id"),
            role_cases: vec![(
                1,
                RelationName::canonicalized("grant_viewer"),
                "viewer".to_string(),
            )],
            user_principal: None,
            team_principal: Some(PrincipalInfo {
                table: table("teams"),
                identity_col: ColumnName::from_stored("id"),
            }),
            team_type: Some(TypeName::canonicalized("team")),
        };
        let query = render_explicit_grants(
            &source,
            &TypeName::canonicalized("docs"),
            &WellKnownTypes::default(),
        );
        assert!(
            query.sql.contains("'team:'"),
            "team-only explicit grants should emit team subjects, got: {}",
            query.sql
        );
        assert!(
            !query.sql.contains("ELSE 'user:'"),
            "team-only explicit grants should fail closed for non-team rows, got: {}",
            query.sql
        );
    }

    #[test]
    fn explicit_grants_mixed_principals_do_not_fallback_to_user_prefix() {
        use crate::generator::ir::{PrincipalInfo, TupleSource};

        let source = TupleSource::ExplicitGrants {
            owner_type: TypeName::canonicalized("doc_grants_owner"),
            grant_table: table("doc_grants"),
            grant_role_col: ColumnName::from_stored("role_level"),
            grant_grantee_col: ColumnName::from_stored("grantee_id"),
            grant_resource_col: ColumnName::from_stored("doc_id"),
            role_cases: vec![(
                1,
                RelationName::canonicalized("grant_viewer"),
                "viewer".to_string(),
            )],
            user_principal: Some(PrincipalInfo {
                table: table("users"),
                identity_col: ColumnName::from_stored("id"),
            }),
            team_principal: Some(PrincipalInfo {
                table: table("teams"),
                identity_col: ColumnName::from_stored("id"),
            }),
            team_type: Some(TypeName::canonicalized("team")),
        };
        let query = render_explicit_grants(
            &source,
            &TypeName::canonicalized("docs"),
            &WellKnownTypes::default(),
        );
        assert!(
            !query.sql.contains("ELSE 'user:'"),
            "mixed-principal explicit grants should not fail open to user subjects, got: {}",
            query.sql
        );
        assert!(
            query.sql.contains("WHEN u.\"id\" IS NOT NULL")
                && query.sql.contains("WHEN t.\"id\" IS NOT NULL"),
            "mixed-principal grants should branch only on explicit principal joins, got: {}",
            query.sql
        );
    }

    #[test]
    fn explicit_grants_team_only_uses_configured_team_type() {
        use crate::generator::ir::{PrincipalInfo, TupleSource};

        let well_known = WellKnownTypes::new(
            "user",
            "group",
            "pg_role",
            "pg_role_scope",
            "request_gate",
            "nobody",
        )
        .expect("valid well-known types");
        let source = TupleSource::ExplicitGrants {
            owner_type: TypeName::canonicalized("doc"),
            grant_table: table("doc_grants"),
            grant_role_col: ColumnName::from_stored("role_level"),
            grant_grantee_col: ColumnName::from_stored("grantee_id"),
            grant_resource_col: ColumnName::from_stored("doc_id"),
            role_cases: vec![(
                1,
                RelationName::canonicalized("viewer"),
                "viewer".to_string(),
            )],
            user_principal: None,
            team_principal: Some(PrincipalInfo {
                table: table("groups"),
                identity_col: ColumnName::from_stored("id"),
            }),
            team_type: Some(TypeName::canonicalized("group")),
        };
        let query = render_explicit_grants(&source, &TypeName::canonicalized("doc"), &well_known);
        assert!(
            query.sql.contains("'group:'"),
            "configured team type missing: {}",
            query.sql
        );
        assert!(
            !query.sql.contains("'team:'"),
            "default team type leaked: {}",
            query.sql
        );
    }

    #[test]
    fn explicit_grants_team_only_encodes_subject_identifier() {
        use crate::generator::ir::{PrincipalInfo, TupleSource};

        let source = TupleSource::ExplicitGrants {
            owner_type: TypeName::canonicalized("doc"),
            grant_table: table("doc_grants"),
            grant_role_col: ColumnName::from_stored("role_level"),
            grant_grantee_col: ColumnName::from_stored("grantee_id"),
            grant_resource_col: ColumnName::from_stored("doc_id"),
            role_cases: vec![(
                1,
                RelationName::canonicalized("viewer"),
                "viewer".to_string(),
            )],
            user_principal: None,
            team_principal: Some(PrincipalInfo {
                table: table("teams"),
                identity_col: ColumnName::from_stored("id"),
            }),
            team_type: Some(TypeName::canonicalized("team")),
        };
        let query = render_explicit_grants(
            &source,
            &TypeName::canonicalized("doc"),
            &WellKnownTypes::default(),
        );
        assert!(
            query
                .sql
                .contains("'team:' || CASE WHEN og.\"grantee_id\"::text"),
            "team ID encoding missing: {}",
            query.sql
        );
    }
}
