//! The kind a request acts as, joined to every row through its table's request-gate object.
//!
//! A request acts as one of the deployment's acting roles, and the policies that reach it
//! are the ones `row_security` answers for that role. The object standing for a guarded
//! type holds, per acting role, the relation `acting_<role>: [pg_role#usage]` and the
//! constant tuple naming that role's `usage`. A check states the role it runs as with the
//! contextual tuple `(user:<subject>, usage, pg_role:<role>)`, so a branch built for one
//! role answers only the requests acting as it.

use super::*;
use crate::generator::unrestricted::row_level_security_is_off;

/// The relation on the request-gate object holding the requests acting as `role`.
///
/// Named after the role where its spelling is already a relation name, and suffixed with
/// a hash of the stored name otherwise, so two roles whose spellings fold together keep
/// two relations.
pub(crate) fn acting_kind_relation_name(role: &str) -> RelationName {
    let readable = canonical_fga_type_name(role);
    if readable.as_str() == role {
        RelationName::canonicalized(clamp_relation_name(format!("acting_{readable}")))
    } else {
        request_gate_relation_name(&format!("acting_{readable}"), role)
    }
}

/// Join the permission object to requests acting as `role`, refusing unnamed row-dependent access.
pub(crate) fn acting_kind_walk<DB: DatabaseLike>(
    role: &str,
    source_table: &TableId,
    db: &DB,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
) -> Option<UsersetExpr> {
    let identity_cols = match resolve_row_identity(source_table, db) {
        Some(columns) => Some(columns),
        None if lookup_table_id(db, source_table)
            .is_some_and(|table| row_level_security_is_off(table, db)) =>
        {
            None
        }
        None => {
            skip_source_without_row_identity(table_plan, source_table, "acting kind links", db);
            return None;
        }
    };
    let relation = acting_kind_relation_name(role);
    let gate_object = table_plan.type_name.to_string();
    let well_known = &table_plan.well_known;
    let gate_type = well_known.request_gate.clone();
    let usage = RolePrivilege::Usage.relation_name();
    ensure_pg_role_relation(all_types, &usage, well_known);
    all_types
        .entry(gate_type.clone())
        .or_insert_with(|| TypePlan::new_with_well_known(gate_type.clone(), well_known))
        .ensure_direct(
            relation.clone(),
            vec![DirectSubject::Userset {
                type_name: well_known.pg_role.clone(),
                relation: usage,
            }],
        );
    table_plan.add_source(TupleSource::ActingKind {
        gate_type: gate_type.clone(),
        gate_object: gate_object.clone(),
        relation: relation.clone(),
        pg_role: role.to_string(),
    });

    let link = table_plan.ensure_direct(
        request_gate_link_relation(),
        vec![DirectSubject::Type(gate_type.clone())],
    );
    let scope = match identity_cols {
        Some(identity_cols) => TupleSource::PolicyScope {
            table: source_table.clone(),
            identity_cols,
            scope_relation: link.clone(),
            scope_type: gate_type,
            scope_object: gate_object,
        },
        None => TupleSource::SingletonScope {
            scope_relation: link.clone(),
            scope_type: gate_type,
            scope_object: gate_object,
        },
    };
    table_plan.add_source(scope);
    Some(UsersetExpr::TupleToUserset {
        tupleset: link,
        computed: relation,
    })
}
