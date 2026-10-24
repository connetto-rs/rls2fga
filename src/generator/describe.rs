//! Derive a [`RecordDescription`] from a [`TupleSource`].
//!
//! Deliberately a second reading of the same shape the renderer reads: one
//! produces SQL for a bulk load, the other structure for one row. They are held
//! together by the differential test, which evaluates every description against
//! the rows its own query returns, so a divergence fails rather than drifts.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::BTreeSet;

use crate::classifier::patterns::{
    AttributeLiteral, AttributeOperator, AttributePredicate, ResidualGuard, ResidualPredicates,
};
use crate::generator::db_lookup::{column_kind, list_element_kind};
use crate::generator::identity::encode_part;
use crate::generator::ir::TupleSource;
use crate::generator::tuple_generator::{quote_sql_identifier, resolve_bridge_columns, TupleQuery};
use crate::generator::well_known::{member_relation, WellKnownTypes, HOLDER_OBJECT_ID};
use crate::parser::sql_parser::DatabaseLike;
use crate::types::RecordContextValue;
use crate::types::{
    BoundQuery, ColumnKind, ColumnRead, ContextRendering, Guard, ObjectKey, Record, RecordContext,
    RecordContextEntry, RecordDerivation, RecordDescription, RecordTemplate, ReplayScope,
    SubjectKey, ValueSource,
};
use crate::types::{ColumnName, RelationName, TableId, TypeName};

/// Sorted, deduplicated table list.
fn tables(names: &[&TableId]) -> Vec<TableId> {
    names
        .iter()
        .map(|name| (*name).clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// A description whose records follow from one row of `table`.
fn from_row(
    table: &TableId,
    object_type: &TypeName,
    object_key: impl Into<ObjectKey>,
    relation: &RelationName,
    subject_type: &TypeName,
    subject_key: impl Into<SubjectKey>,
    guards: Vec<Guard>,
) -> RecordDescription {
    described(
        table,
        RecordTemplate {
            object_type: object_type.clone(),
            object_key: object_key.into(),
            relation: relation.clone(),
            subject_type: subject_type.clone(),
            subject_key: subject_key.into(),
            context: None,
        },
        guards,
    )
}

/// A description of records a template already spells out.
///
/// Takes the template rather than its six fields, since the caller that needs a request
/// context is building one anyway and the fields travelling separately made this the
/// widest signature in the module.
fn described(table: &TableId, template: RecordTemplate, guards: Vec<Guard>) -> RecordDescription {
    RecordDescription {
        tables: tables(&[table]),
        derivation: RecordDerivation::FromRow {
            table: table.clone(),
            template: Box::new(template),
            guards,
        },
    }
}

/// Bind the whole-table query to one row, which every joining shape's query ends in a
/// position to accept: each closes with a `WHERE` and a `;`.
///
/// Takes the rendered query rather than its text, so the condition its rows carry cannot
/// be separated from the SQL that projects it.
///
/// `None` for an empty key, since a query bound to nothing names every row.
fn bind(
    query: &TupleQuery,
    table: &TableId,
    key_columns: &[ColumnName],
    predicate: &str,
    scope: ReplayScope,
) -> Option<BoundQuery> {
    let body = query.sql.strip_suffix(';')?;
    if key_columns.is_empty() || !body.contains("WHERE ") {
        return None;
    }
    // The bound predicate filters rows, so it belongs in the WHERE. An aggregated query
    // ends in GROUP BY, so the predicate goes just before it. A plain query ends in its
    // WHERE, so it goes at the end.
    let sql = match body.split_once("\nGROUP BY ") {
        Some((filter, grouping)) => format!("{filter}\nAND {predicate}\nGROUP BY {grouping};"),
        None => format!("{body}\nAND {predicate};"),
    };
    BoundQuery::new(
        table.clone(),
        key_columns.to_vec(),
        sql,
        query.condition.clone(),
        scope,
    )
    .ok()
}

/// The condition [`bind`] appends: every column compared to its own bound value.
///
/// One equality per column, numbered in order, because a compound key names a row only
/// when all of it is given. The only place a bound condition is spelled, and it escapes
/// through the renderer's own [`quote_sql_identifier`] rather than wrapping the name in
/// quotes, because a column whose stored name carries a `"` is not the column `"a"b"`
/// names and `PostgreSQL` does not parse it.
///
/// `qualifier` is the alias the rendered query gave the table, absent where it gave none.
/// It is a generated alias rather than a schema name, so it needs no escaping.
fn bound_eq(qualifier: Option<&str>, columns: &[ColumnName]) -> String {
    columns
        .iter()
        .enumerate()
        .map(|(index, column)| {
            let quoted = quote_sql_identifier(column.as_str());
            let placeholder = index + 1;
            match qualifier {
                Some(alias) => format!("{alias}.{quoted} = ${placeholder}"),
                None => format!("{quoted} = ${placeholder}"),
            }
        })
        .collect::<Vec<String>>()
        .join(" AND ")
}

/// The whole-table query for this one source, which is what a bound query extends.
///
/// `None` where the renderer stands advice in place of a query, since advice loads nothing
/// and there is no text to bind.
fn rendered(query: &TupleQuery) -> Option<&TupleQuery> {
    query.skipped.is_none().then_some(query)
}

/// The description for a residual only SQL can evaluate.
///
/// A residual reading a relation moves with rows no key names, so no key narrows its
/// replay and the table list has to name those relations too.
fn residual_description(
    query: &TupleQuery,
    table: &TableId,
    key_columns: &[ColumnName],
    extra_predicates: &ResidualPredicates,
    scope: ReplayScope,
    reason: String,
) -> RecordDescription {
    let relations = extra_predicates.relations();
    if relations.is_empty() {
        return RecordDescription {
            tables: tables(&[table]),
            derivation: RecordDerivation::Joined {
                queries: bind(
                    query,
                    table,
                    key_columns,
                    &bound_eq(None, key_columns),
                    scope,
                )
                .into_iter()
                .collect(),
                reason,
            },
        };
    }
    let read: Vec<&TableId> = core::iter::once(table).chain(relations.iter()).collect();
    RecordDescription {
        tables: tables(&read),
        derivation: RecordDerivation::WholeShape {
            query: query.sql.clone(),
            condition: query.condition.clone(),
            scope,
            reason,
        },
    }
}

/// One value source per key column, in declared order.
///
/// A missing part yields no record, so a `NOT NULL` guard would duplicate the key.
fn column_read<DB: DatabaseLike>(table: &TableId, column: &ColumnName, db: &DB) -> ColumnRead {
    ColumnRead::new(column.clone(), column_kind(table, column.as_str(), db))
}

fn value_column<DB: DatabaseLike>(table: &TableId, column: &ColumnName, db: &DB) -> ValueSource {
    ValueSource::Column(column_read(table, column, db))
}

fn list_column<DB: DatabaseLike>(table: &TableId, column: &ColumnName, db: &DB) -> ValueSource {
    ValueSource::ListElements(ColumnRead::new(
        column.clone(),
        list_element_kind(table, column.as_str(), db),
    ))
}

fn json_path<DB: DatabaseLike>(
    table: &TableId,
    column: &ColumnName,
    path: &[String],
    db: &DB,
) -> ValueSource {
    ValueSource::JsonPath {
        column: column_read(table, column, db),
        path: path.to_vec(),
    }
}

fn composite_subject<DB: DatabaseLike>(
    table: &TableId,
    first: &ColumnName,
    rest: &[ColumnName],
    db: &DB,
) -> SubjectKey {
    SubjectKey::composite_sources(
        value_column(table, first, db),
        rest.iter()
            .map(|column| value_column(table, column, db))
            .collect(),
    )
}
fn subject_column<DB: DatabaseLike>(table: &TableId, column: &ColumnName, db: &DB) -> SubjectKey {
    SubjectKey::new(value_column(table, column, db))
}

fn not_null<DB: DatabaseLike>(table: &TableId, column: &ColumnName, db: &DB) -> Guard {
    Guard::NotNull(column_read(table, column, db))
}

/// Guards `column` against NULL and carries it into the record context under `key`.
fn carry_context_column<DB: DatabaseLike>(
    table: &TableId,
    column: &ColumnName,
    key: &str,
    db: &DB,
    guards: &mut Vec<Guard>,
    entries: &mut Vec<RecordContextEntry>,
) {
    guards.push(not_null(table, column, db));
    entries.push(RecordContextEntry {
        key: key.to_owned(),
        value: value_column(table, column, db),
        rendering: ContextRendering::Json,
    });
}

fn is_true<DB: DatabaseLike>(table: &TableId, column: &ColumnName, db: &DB) -> Guard {
    Guard::IsTrue(column_read(table, column, db))
}

fn key_parts<DB: DatabaseLike>(
    table: &TableId,
    identity_cols: &[ColumnName],
    db: &DB,
) -> Vec<ValueSource> {
    identity_cols
        .iter()
        .map(|column| value_column(table, column, db))
        .collect()
}

/// Describe the records `source` produces, or `None` where it produces none.
pub(crate) fn describe_tuple_source<DB: DatabaseLike>(
    source: &TupleSource,
    owner_type: &TypeName,
    query: &TupleQuery,
    well_known: &WellKnownTypes,
    db: &DB,
) -> Option<RecordDescription> {
    match source {
        TupleSource::DirectOwnership {
            table,
            identity_cols,
            owner_col,
            relation,
        } => Some(from_row(
            table,
            owner_type,
            ObjectKey::new(key_parts(table, identity_cols, db)),
            relation,
            &well_known.user,
            value_column(table, owner_col, db),
            vec![not_null(table, owner_col, db)],
        )),

        // One record per element, and the evaluator drops a null element exactly
        // as `WHERE member IS NOT NULL` does.
        TupleSource::ArrayMembership {
            table,
            identity_cols,
            array_col,
            relation,
        } => Some(from_row(
            table,
            owner_type,
            ObjectKey::new(key_parts(table, identity_cols, db)),
            relation,
            &well_known.user,
            list_column(table, array_col, db),
            Vec::new(),
        )),

        TupleSource::JsonbFieldOwnership {
            table,
            identity_cols,
            column,
            path,
            relation,
        } => Some(from_row(
            table,
            owner_type,
            ObjectKey::new(key_parts(table, identity_cols, db)),
            relation,
            &well_known.user,
            json_path(table, column, path, db),
            Vec::new(),
        )),

        // The owner identity is the principal of the same name, which one principal row
        // decides on its own.
        TupleSource::OwnerIdentity {
            owner_type: identity_type,
            principal_table,
            principal_identity_col,
            subject_type,
            relation,
        } => Some(from_row(
            principal_table,
            identity_type,
            ObjectKey::new(key_parts(
                principal_table,
                core::slice::from_ref(principal_identity_col),
                db,
            )),
            relation,
            subject_type,
            subject_column(principal_table, principal_identity_col, db),
            vec![not_null(principal_table, principal_identity_col, db)],
        )),

        TupleSource::ExplicitGrants {
            owner_type: granted_type,
            grant_table,
            grant_resource_col,
            role_cases,
            user_principal,
            team_principal,
            ..
        } => {
            if role_cases.is_empty() {
                return None;
            }
            let query = rendered(query)?;
            let mut read = vec![grant_table];
            if let Some(principal) = user_principal {
                read.push(&principal.table);
            }
            if let Some(principal) = team_principal {
                read.push(&principal.table);
            }
            // The grantee's type is what the row does not say, so one grant row does not
            // decide its own record. The owner it names is the object either way, so the
            // replay is keyed on that column and its slice is that one owner's grants.
            let granted = core::slice::from_ref(grant_resource_col);
            Some(RecordDescription {
                tables: tables(&read),
                derivation: RecordDerivation::Joined {
                    queries: bind(
                        query,
                        grant_table,
                        granted,
                        &bound_eq(Some("og"), granted),
                        ReplayScope::Object {
                            object_type: granted_type.clone(),
                            relations: role_cases
                                .iter()
                                .map(|(_, relation, _)| relation.clone())
                                .collect(),
                        },
                    )
                    .into_iter()
                    .collect(),
                    reason: "a grant row does not say whether its grantee is a user or a team"
                        .to_string(),
                },
            })
        }

        TupleSource::TeamMembership {
            membership_table,
            team_col,
            user_col,
            team_type,
        } => Some(from_row(
            membership_table,
            team_type,
            value_column(membership_table, team_col, db),
            &member_relation(),
            &well_known.user,
            value_column(membership_table, user_col, db),
            vec![
                not_null(membership_table, team_col, db),
                not_null(membership_table, user_col, db),
            ],
        )),

        // A residual the row image can evaluate becomes guards, so the
        // records stay a function of one membership row and a delete of that
        // row reports its records as removed. A residual only SQL can
        // evaluate leaves the shape joined, and its query is then what keeps
        // the records current.
        TupleSource::ExistsMembership {
            join_table,
            fk_cols,
            user_col,
            parent_type,
            relation,
            extra_predicates,
            gate,
        } => {
            let mut guards: Vec<Guard> = fk_cols
                .iter()
                .map(|column| not_null(join_table, column, db))
                .collect();
            guards.push(not_null(join_table, user_col, db));
            let Some(gate) = gate else {
                let Some(residual) = residual_guards(join_table, extra_predicates, db) else {
                    let predicate = extra_predicates.sql().unwrap_or_default();
                    let query = rendered(query)?;
                    return Some(residual_description(
                        query,
                        join_table,
                        fk_cols,
                        extra_predicates,
                        ReplayScope::Object {
                            object_type: parent_type.clone(),
                            relations: vec![relation.clone()],
                        },
                        format!(
                            "the membership row carries a residual predicate only SQL can \
                             evaluate: {predicate}"
                        ),
                    ));
                };
                guards.extend(residual);
                return Some(from_row(
                    join_table,
                    parent_type,
                    ObjectKey::new(key_parts(join_table, fk_cols, db)),
                    relation,
                    &well_known.user,
                    value_column(join_table, user_col, db),
                    guards,
                ));
            };
            if gate.aggregate {
                // Several rows can key the same (object, user), so the latest deadline is
                // read by querying the changed parent's slice. The row alone cannot say it.
                let query = rendered(query)?;
                return Some(residual_description(
                    query,
                    join_table,
                    fk_cols,
                    extra_predicates,
                    ReplayScope::Object {
                        object_type: parent_type.clone(),
                        relations: vec![relation.clone()],
                    },
                    format!(
                        "several membership rows can grant one (object, user), so the latest \
                         deadline is read by querying: condition {}",
                        gate.condition
                    ),
                ));
            }
            // The clock joined the condition, so the member row alone decides the record:
            // its guards are the residual's row-decidable conjuncts, and each carried column
            // enters the context the check reads the clock against.
            guards.extend(
                extra_predicates
                    .row_guards()
                    .into_iter()
                    .filter_map(|guard| guard_from_residual(join_table, guard, db)),
            );
            let mut entries = Vec::with_capacity(gate.context.len());
            for column in &gate.context {
                carry_context_column(
                    join_table,
                    &column.column,
                    &column.parameter,
                    db,
                    &mut guards,
                    &mut entries,
                );
            }
            Some(described(
                join_table,
                RecordTemplate {
                    object_type: parent_type.clone(),
                    object_key: ObjectKey::new(key_parts(join_table, fk_cols, db)),
                    relation: relation.clone(),
                    subject_type: well_known.user.clone(),
                    subject_key: subject_column(join_table, user_col, db),
                    context: Some(RecordContext {
                        condition: gate.condition.clone(),
                        entries,
                    }),
                },
                guards,
            ))
        }

        TupleSource::ParentBridge {
            table,
            fk_cols,
            parent_type,
            relation,
        } => {
            // The renderer emits a TODO comment rather than a query here, so
            // there are no records to describe.
            let (object_cols, parent_ref_cols) = resolve_bridge_columns(table, fk_cols, db)?;
            let (first_ref, rest_refs) = parent_ref_cols.split_first()?;
            let mut guards: Vec<Guard> = object_cols
                .iter()
                .map(|column| not_null(table, column, db))
                .collect();
            guards.extend(
                parent_ref_cols
                    .iter()
                    .map(|column| not_null(table, column, db)),
            );
            Some(from_row(
                table,
                owner_type,
                ObjectKey::new(key_parts(table, &object_cols, db)),
                relation,
                parent_type,
                composite_subject(table, first_ref, rest_refs, db),
                guards,
            ))
        }

        TupleSource::PublicFlag {
            table,
            identity_cols,
            flag_col,
            relation,
        } => Some(from_row(
            table,
            owner_type,
            ObjectKey::new(key_parts(table, identity_cols, db)),
            relation,
            &well_known.user,
            SubjectKey::wildcard(),
            vec![is_true(table, flag_col, db)],
        )),

        TupleSource::RowPresenceGate {
            table,
            identity_cols,
            columns,
            relation,
        } => Some(from_row(
            table,
            owner_type,
            ObjectKey::new(key_parts(table, identity_cols, db)),
            relation,
            &well_known.user,
            SubjectKey::wildcard(),
            columns
                .iter()
                .map(|column| not_null(table, column, db))
                .collect(),
        )),

        TupleSource::ConstantTrue {
            table,
            identity_cols,
            relation,
        } => Some(from_row(
            table,
            owner_type,
            ObjectKey::new(key_parts(table, identity_cols, db)),
            relation,
            &well_known.user,
            SubjectKey::wildcard(),
            Vec::new(),
        )),

        TupleSource::PolicyScope {
            table,
            identity_cols,
            scope_relation,
            scope_type,
            scope_object,
        } => Some(from_row(
            table,
            owner_type,
            ObjectKey::new(key_parts(table, identity_cols, db)),
            scope_relation,
            scope_type,
            ValueSource::Literal(scope_object.clone()),
            Vec::new(),
        )),

        // The roles a scope admits follow from the policy, so the fact is the whole
        // description: no row is read, no table is named, and a consumer replaying a
        // changed row never reaches it.
        TupleSource::PolicyScopeRoles {
            scope_type,
            scope_object,
            relation,
            pg_role,
        } => Some(RecordDescription {
            tables: Vec::new(),
            derivation: RecordDerivation::Constant {
                // Spelled exactly as the query spells it, since the differential test
                // compares the two.
                record: Record {
                    object: format!("{scope_type}:{}", encode_part(scope_object)),
                    relation: relation.clone(),
                    subject: format!("{}:{}", well_known.pg_role, encode_part(pg_role)),
                    context: None,
                },
            },
        }),

        // The constant a gate tests follows from the policy, so the fact is the whole
        // description, exactly as for the roles a scope admits.
        TupleSource::RequestGateEntry {
            gate_type,
            gate_object,
            relation,
            condition,
            row_parameter,
            atom,
        } => Some(RecordDescription {
            tables: Vec::new(),
            derivation: RecordDerivation::Constant {
                record: Record {
                    object: format!("{gate_type}:{}", encode_part(gate_object)),
                    relation: relation.clone(),
                    subject: format!("{}:*", well_known.user),
                    context: Some(RecordContextValue {
                        condition: condition.clone(),
                        values: [(row_parameter.clone(), atom.value.clone())]
                            .into_iter()
                            .collect(),
                    }),
                },
            },
        }),

        // The guard reaches the description as structure, so the evaluator applies
        // the same comparison the query puts in its WHERE.
        TupleSource::AttributeGate {
            table,
            identity_cols,
            predicate,
            relation,
        } => {
            let Some(guard) = compare_guard(table, predicate, db) else {
                let query = rendered(query)?;
                return Some(RecordDescription {
                    tables: tables(&[table]),
                    derivation: RecordDerivation::Joined {
                        queries: bind(
                            query,
                            table,
                            identity_cols,
                            &bound_eq(None, identity_cols),
                            ReplayScope::Object {
                                object_type: owner_type.clone(),
                                relations: vec![relation.clone()],
                            },
                        )
                        .into_iter()
                        .collect(),
                        reason: format!("the row comparison on {} needs SQL", predicate.column),
                    },
                });
            };
            Some(from_row(
                table,
                owner_type,
                ObjectKey::new(key_parts(table, identity_cols, db)),
                relation,
                &well_known.user,
                SubjectKey::wildcard(),
                vec![guard],
            ))
        }

        // The record is a function of the row alone: the comparison happens
        // at check time, and what the row contributes to it travels in the
        // record's context, exactly as the sibling session-attribute gate
        // carries it.
        TupleSource::ConditionalAttributeGate {
            table,
            identity_cols,
            relation,
            condition,
            row_parameter,
            column,
        } => Some(described(
            table,
            RecordTemplate {
                object_type: owner_type.clone(),
                object_key: ObjectKey::new(key_parts(table, identity_cols, db)),
                relation: relation.clone(),
                subject_type: well_known.user.clone(),
                subject_key: SubjectKey::wildcard(),
                context: Some(RecordContext {
                    condition: condition.clone(),
                    entries: vec![RecordContextEntry {
                        key: row_parameter.clone(),
                        value: value_column(table, column, db),
                        rendering: ContextRendering::Json,
                    }],
                }),
            },
            vec![not_null(table, column, db)],
        )),

        // The row carries its side of the comparison, so the description carries the
        // same key the tuple SQL puts in the context. The request supplies the rest, and
        // the recipe rather than the record says how the two meet.
        TupleSource::SessionAttributeGate {
            table,
            identity_cols,
            relation,
            row_parameter,
            column,
            condition,
            ..
        } => Some(described(
            table,
            RecordTemplate {
                object_type: owner_type.clone(),
                object_key: ObjectKey::new(key_parts(table, identity_cols, db)),
                relation: relation.clone(),
                subject_type: well_known.user.clone(),
                subject_key: SubjectKey::wildcard(),
                context: Some(RecordContext {
                    condition: condition.clone(),
                    entries: vec![RecordContextEntry {
                        key: row_parameter.clone(),
                        value: value_column(table, column, db),
                        rendering: ContextRendering::SqlText,
                    }],
                }),
            },
            vec![not_null(table, column, db)],
        )),

        // The record is a function of the share row alone: the object is keyed on the
        // share's own primary key, and the comparison the request completes travels in
        // the record's context, exactly as the sibling session-attribute gate carries it.
        // A residual only SQL can evaluate leaves the shape joined, and its query is then
        // what keeps the records current.
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
            let mut entries = vec![RecordContextEntry {
                key: row_parameter.clone(),
                value: value_column(join_table, member_col, db),
                rendering: ContextRendering::SqlText,
            }];
            let mut guards = vec![not_null(join_table, member_col, db)];
            if temporal_context.is_empty() {
                let Some(residual) = residual_guards(join_table, extra_predicates, db) else {
                    let predicate = extra_predicates.sql().unwrap_or_default();
                    let query = rendered(query)?;
                    return Some(residual_description(
                        query,
                        join_table,
                        identity_cols,
                        extra_predicates,
                        ReplayScope::Object {
                            object_type: share_type.clone(),
                            relations: vec![relation.clone()],
                        },
                        format!(
                            "the share row carries a residual predicate only SQL can evaluate: \
                             {predicate}"
                        ),
                    ));
                };
                guards.extend(residual);
            } else {
                // The clock joined the condition, so the row alone decides the record: its
                // guards are the residual's row-decidable conjuncts, and each carried column
                // enters the context beside the member the set compares.
                guards.extend(
                    extra_predicates
                        .row_guards()
                        .into_iter()
                        .filter_map(|guard| guard_from_residual(join_table, guard, db)),
                );
                for gate in temporal_context {
                    carry_context_column(
                        join_table,
                        &gate.column,
                        &gate.parameter,
                        db,
                        &mut guards,
                        &mut entries,
                    );
                }
            }
            Some(described(
                join_table,
                RecordTemplate {
                    object_type: share_type.clone(),
                    object_key: ObjectKey::new(key_parts(join_table, identity_cols, db)),
                    relation: relation.clone(),
                    subject_type: well_known.user.clone(),
                    subject_key: SubjectKey::wildcard(),
                    context: Some(RecordContext {
                        condition: condition.clone(),
                        entries,
                    }),
                },
                guards,
            ))
        }

        // One record per membership row: the object is the row's own witness, the
        // subject the member it names, and its clock values travel in the context.
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
            let mut guards = vec![not_null(join_table, user_col, db)];
            guards.extend(
                extra_predicates
                    .row_guards()
                    .into_iter()
                    .filter_map(|guard| guard_from_residual(join_table, guard, db)),
            );
            let mut entries = Vec::with_capacity(context.len());
            for gate in context {
                carry_context_column(
                    join_table,
                    &gate.column,
                    &gate.parameter,
                    db,
                    &mut guards,
                    &mut entries,
                );
            }
            Some(described(
                join_table,
                RecordTemplate {
                    object_type: share_type.clone(),
                    object_key: ObjectKey::new(key_parts(join_table, identity_cols, db)),
                    relation: relation.clone(),
                    subject_type: well_known.user.clone(),
                    subject_key: subject_column(join_table, user_col, db),
                    context: Some(RecordContext {
                        condition: condition.clone(),
                        entries,
                    }),
                },
                guards,
            ))
        }

        // Each share row links its guarded object to its own share object, so the record
        // follows from the one join row: the object is the guarded row named by the
        // object columns, the subject the share named by the row's own identity.
        TupleSource::ShareBridge {
            join_table,
            object_cols,
            identity_cols,
            guarded_type,
            share_type,
            relation,
        } => {
            // An empty key names no share, so the source produces no records to describe.
            let (first, rest) = identity_cols.split_first()?;
            let mut guards: Vec<_> = object_cols
                .iter()
                .map(|column| not_null(join_table, column, db))
                .collect();
            guards.extend(
                identity_cols
                    .iter()
                    .map(|column| not_null(join_table, column, db)),
            );
            let object_parts: Vec<_> = object_cols
                .iter()
                .map(|column| value_column(join_table, column, db))
                .collect();
            if object_parts.is_empty() {
                return None;
            }
            Some(from_row(
                join_table,
                guarded_type,
                ObjectKey::new(object_parts),
                relation,
                share_type,
                composite_subject(join_table, first, rest, db),
                guards,
            ))
        }

        // Every row of the table points at the one holder object.
        TupleSource::HolderBridge {
            table,
            identity_cols,
            relation,
            holder_type,
        } => Some(from_row(
            table,
            owner_type,
            ObjectKey::new(key_parts(table, identity_cols, db)),
            relation,
            holder_type,
            ValueSource::Literal(HOLDER_OBJECT_ID.to_string()),
            Vec::new(),
        )),

        // One record per membership row: the object is the one holder, the subject the
        // row's own witness.
        TupleSource::HolderShares {
            member_table,
            identity_cols,
            holder_type,
            share_type,
            relation,
        } => {
            let (first, rest) = identity_cols.split_first()?;
            let guards = identity_cols
                .iter()
                .map(|column| not_null(member_table, column, db))
                .collect();
            Some(from_row(
                member_table,
                holder_type,
                ObjectKey::new(vec![ValueSource::Literal(HOLDER_OBJECT_ID.to_string())]),
                relation,
                share_type,
                composite_subject(member_table, first, rest, db),
                guards,
            ))
        }

        // The holder is one object, so the object side is fixed and each member row
        // names a user. Two rows naming the same user write one record, which a set
        // of records collapses exactly as the query's DISTINCT does. A residual the
        // row image can evaluate becomes guards, and one only SQL can evaluate
        // leaves the shape joined, its query keeping the records current.
        TupleSource::HolderMembers {
            holder_type,
            member_table,
            user_col,
            extra_predicates,
            gate,
            relation,
        } => {
            let mut guards = vec![not_null(member_table, user_col, db)];
            let Some(gate) = gate else {
                let Some(residual) = residual_guards(member_table, extra_predicates, db) else {
                    let predicate = extra_predicates.sql().unwrap_or_default();
                    let query = rendered(query)?;
                    return Some(residual_description(
                        query,
                        member_table,
                        core::slice::from_ref(user_col),
                        extra_predicates,
                        ReplayScope::Subject {
                            subject_type: well_known.user.clone(),
                            relation: relation.clone(),
                            object_type: holder_type.clone(),
                        },
                        format!(
                            "the member row carries a residual predicate only SQL can evaluate: \
                             {predicate}"
                        ),
                    ));
                };
                guards.extend(residual);
                return Some(from_row(
                    member_table,
                    holder_type,
                    ValueSource::Literal(HOLDER_OBJECT_ID.to_string()),
                    relation,
                    &well_known.user,
                    value_column(member_table, user_col, db),
                    guards,
                ));
            };
            if gate.aggregate {
                // Several member rows can name one user with different deadlines, and the
                // holder collapses them, so the latest deadline is read by querying that
                // user's slice rather than settled from one row.
                let query = rendered(query)?;
                return Some(residual_description(
                    query,
                    member_table,
                    core::slice::from_ref(user_col),
                    extra_predicates,
                    ReplayScope::Subject {
                        subject_type: well_known.user.clone(),
                        relation: relation.clone(),
                        object_type: holder_type.clone(),
                    },
                    format!(
                        "several member rows can name one user, so the latest deadline is read \
                         by querying: condition {}",
                        gate.condition
                    ),
                ));
            }
            // The clock joined the condition, so the member row alone decides the record.
            guards.extend(
                extra_predicates
                    .row_guards()
                    .into_iter()
                    .filter_map(|guard| guard_from_residual(member_table, guard, db)),
            );
            let mut entries = Vec::with_capacity(gate.context.len());
            for column in &gate.context {
                carry_context_column(
                    member_table,
                    &column.column,
                    &column.parameter,
                    db,
                    &mut guards,
                    &mut entries,
                );
            }
            Some(described(
                member_table,
                RecordTemplate {
                    object_type: holder_type.clone(),
                    object_key: ObjectKey::new(vec![ValueSource::Literal(
                        HOLDER_OBJECT_ID.to_string(),
                    )]),
                    relation: relation.clone(),
                    subject_type: well_known.user.clone(),
                    subject_key: subject_column(member_table, user_col, db),
                    context: Some(RecordContext {
                        condition: gate.condition.clone(),
                        entries,
                    }),
                },
                guards,
            ))
        }

        TupleSource::Skipped { .. } => None,
    }
}

/// The residual as guards, or [`None`] when any conjunct needs SQL.
fn residual_guards<DB: DatabaseLike>(
    table: &TableId,
    residuals: &ResidualPredicates,
    db: &DB,
) -> Option<Vec<Guard>> {
    residuals.guards().and_then(|guards| {
        guards
            .into_iter()
            .map(|guard| guard_from_residual(table, guard, db))
            .collect()
    })
}

/// One residual guard as the record guard that decides it.
fn guard_from_residual<DB: DatabaseLike>(
    table: &TableId,
    guard: ResidualGuard,
    db: &DB,
) -> Option<Guard> {
    match guard {
        ResidualGuard::IsTrue(column) => Some(is_true(table, &column, db)),
        ResidualGuard::NotNull(column) => Some(not_null(table, &column, db)),
        ResidualGuard::Compare(predicate) => compare_guard(table, &predicate, db),
    }
}

fn compare_guard<DB: DatabaseLike>(
    table: &TableId,
    predicate: &AttributePredicate,
    db: &DB,
) -> Option<Guard> {
    let column = column_read(table, &predicate.column, db);
    let row_decides = matches!(
        (column.kind(), &predicate.value),
        (ColumnKind::Bool, AttributeLiteral::Boolean(_))
            | (
                ColumnKind::Integer | ColumnKind::Decimal,
                AttributeLiteral::Number(_)
            )
    ) || matches!(
        (column.kind(), &predicate.value, predicate.operator),
        (
            ColumnKind::Text,
            AttributeLiteral::Text(_),
            AttributeOperator::Eq | AttributeOperator::NotEq
        )
    );
    row_decides.then_some(Guard::Compare {
        column,
        predicate: predicate.clone(),
    })
}
