//! Expanding a policy call to a declared single-expression `LANGUAGE sql`
//! function, so the documented workaround for policy self-recursion translates
//! from the dump alone.
//!
//! Every gate refuses by returning `Expansion::Refused`, which the classifier
//! turns into an [`crate::classifier::patterns::UnclassifiedExpr`] refusal, so a
//! body the expansion cannot prove falls closed rather than widening access.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use core::cell::{Cell, RefCell};
use core::ops::ControlFlow;

use sqlparser::ast::{
    Expr, FunctionArg, FunctionArgExpr, FunctionArguments, FunctionCalledOnNull, FunctionSecurity,
    FunctionSetValue, Ident, ObjectName, ObjectNamePart, TableFactor, Value, Visit, VisitMut,
    Visitor, VisitorMut,
};

use crate::classifier::function_registry::FunctionRegistry;
use crate::parser::function_analyzer::{body_reads_effective_user, body_single_projection};
use crate::parser::names::{
    lookup_table, stored_ident_name, stored_identifier, stored_relation_name, table_has_column,
    unquote_identifier,
};
use crate::parser::sql_parser::{DatabaseLike, FunctionLike, RoleLike, TableLike};
use crate::types::{ColumnName, TableId};

/// Expansions one classification may perform, bounding the work a schema can
/// demand: a body that doubles its calls per level is cut here rather than
/// growing geometrically under the depth limit alone.
const EXPANSION_BUDGET: u32 = 32;

/// What one classification has already expanded.
///
/// The stack cuts call cycles by name, and it must survive the recognizer
/// re-entries into classification, so it rides beside the depth counter rather
/// than resetting with it.
pub struct ExpansionState {
    in_flight: RefCell<Vec<String>>,
    /// Tables whose readability a walk of their policies is deciding, which a residual
    /// inside that walk cannot lean on.
    readability_in_flight: RefCell<Vec<TableId>>,
    budget: Cell<u32>,
    owner_reads: Cell<u32>,
}

impl ExpansionState {
    /// A fresh state, which is what one whole clause classification carries.
    #[must_use]
    pub fn new() -> Self {
        Self {
            in_flight: RefCell::new(Vec::new()),
            readability_in_flight: RefCell::new(Vec::new()),
            budget: Cell::new(EXPANSION_BUDGET),
            owner_reads: Cell::new(0),
        }
    }
}

impl Default for ExpansionState {
    fn default() -> Self {
        Self::new()
    }
}

impl ExpansionState {
    fn expanding(&self, name: &str) -> bool {
        self.in_flight.borrow().iter().any(|held| held == name)
    }

    /// Record that `name` is being expanded. Paired with [`ExpansionState::leave`].
    pub(crate) fn enter(&self, name: String) {
        self.in_flight.borrow_mut().push(name);
    }

    pub(crate) fn leave(&self) {
        self.in_flight.borrow_mut().pop();
    }

    /// Run `walk` deciding the readability of `table`, or [`None`] where a walk of the
    /// same table is already deciding it further up.
    pub(crate) fn deciding_readability<T>(
        &self,
        table: &TableId,
        walk: impl FnOnce() -> T,
    ) -> Option<T> {
        if self.readability_in_flight.borrow().contains(table) {
            return None;
        }
        self.readability_in_flight.borrow_mut().push(table.clone());
        let decided = walk();
        self.readability_in_flight.borrow_mut().pop();
        Some(decided)
    }

    /// True while a definer body whose reads provably bypass row level security
    /// is being classified, so a scan of the guarded table is the owner's read
    /// rather than the recursion `PostgreSQL` refuses to plan.
    pub(crate) fn reading_as_owner(&self) -> bool {
        self.owner_reads.get() > 0
    }

    pub(crate) fn enter_owner_read(&self) {
        self.owner_reads.set(self.owner_reads.get() + 1);
    }

    pub(crate) fn leave_owner_read(&self) {
        self.owner_reads.set(self.owner_reads.get() - 1);
    }

    fn take_budget(&self) -> bool {
        let left = self.budget.get();
        if left == 0 {
            return false;
        }
        self.budget.set(left - 1);
        true
    }
}

/// How a call to a declared function expands.
pub(crate) enum Expansion {
    /// The substituted body, ready to classify in the call's place.
    Body {
        /// The called function, as spelled in its declaration.
        function: String,
        /// The name `PostgreSQL` stores for it, which is what tells two declarations
        /// differing only by quoting apart on the expansion stack.
        identity: String,
        /// The body's table reads run as an owner `PostgreSQL` lets past those
        /// tables' policies.
        reads_bypass_rls: bool,
        /// Row columns that must be non-null before the body can return true.
        presence_columns: Vec<ColumnName>,
        /// The body with the call-site arguments substituted.
        expr: Box<Expr>,
    },
    /// The call names a declared function the expansion cannot prove, so the
    /// clause falls closed with this reason.
    Refused {
        /// Why the call is not expanded.
        reason: String,
    },
}

/// Expand `expr` when it is a call to a declared, unregistered,
/// single-expression `LANGUAGE sql` function.
///
/// `None` means the expression is not such a call, and the caller's ordinary
/// blame path stands.
pub(crate) fn expand_function_call<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    table: &str,
    state: &ExpansionState,
) -> Option<Expansion> {
    let Expr::Function(func) = expr else {
        return None;
    };
    // A window, filter or parameterized call is not the plain boolean call this
    // expands, and an argument list with modifiers is not plain either.
    if func.over.is_some()
        || func.filter.is_some()
        || func.null_treatment.is_some()
        || !matches!(func.parameters, FunctionArguments::None)
        || !func.within_group.is_empty()
    {
        return None;
    }
    let FunctionArguments::List(arg_list) = &func.args else {
        return None;
    };
    if arg_list.duplicate_treatment.is_some() || !arg_list.clauses.is_empty() {
        return None;
    }
    let mut call_args = Vec::with_capacity(arg_list.args.len());
    for arg in &arg_list.args {
        let FunctionArg::Unnamed(FunctionArgExpr::Expr(value)) = arg else {
            return None;
        };
        call_args.push(value.clone());
    }

    let call_name = func.name.to_string();
    // A declaration wins: a registered semantic, or the standing owner-bound
    // refusal, is already how this call translates.
    if registry.get(&call_name).is_some() {
        return None;
    }
    let terminal = stored_relation_name(&call_name);
    if registry.is_owner_bound_accessor(&call_name) {
        return None;
    }

    let named: Vec<&DB::Function> = db
        .functions()
        .filter(|declared| call_matches_declared(&func.name, *declared, db))
        .collect();
    let first_named = named.first()?;
    let function_name = first_named.name().to_string();
    let candidates: Vec<&DB::Function> = named
        .iter()
        .copied()
        .filter(|declared| declared.argument_names(db).count() == call_args.len())
        .collect();
    let function = match candidates.as_slice() {
        [] => {
            return Some(refused(format!(
                "Function '{function_name}' is declared with a different argument count \
                 than this call passes, so the call is not the declared body"
            )))
        }
        [only] => *only,
        _ => {
            return Some(refused(format!(
                "More than one declaration of '{function_name}' matches this call, so \
                 which body the call runs cannot be known"
            )))
        }
    };

    if state.expanding(&terminal) {
        return Some(refused(format!(
            "Expanding '{function_name}' reaches a call of itself, and the call cycle \
             is not translated"
        )));
    }
    if !state.take_budget() {
        return Some(refused(format!(
            "Expanding '{function_name}' exceeds the expansion budget for one clause, \
             so the remainder is not translated"
        )));
    }

    match function.stored_language().as_deref() {
        Some("sql") => {}
        Some(_) => {
            let language = function.language().unwrap_or("unknown");
            return Some(refused(format!(
                "Function '{function_name}' is LANGUAGE {language}, and only a \
                 single-expression LANGUAGE sql body expands"
            )));
        }
        None => {
            return Some(refused(format!(
                "Function '{function_name}' declares no language, and only a \
                 single-expression LANGUAGE sql body expands"
            )))
        }
    }

    let (mut body, string_body) = match (function.body_expression(), function.body()) {
        (Some(parsed), _) => (parsed.clone(), false),
        (None, Some(text)) => match body_single_projection(text) {
            Some(projected) => (projected, true),
            None => {
                return Some(refused(format!(
                    "Function '{function_name}' has no single-expression SELECT body, \
                     so the call is not expanded"
                )))
            }
        },
        (None, None) => {
            return Some(refused(format!(
                "Function '{function_name}' has no readable body, so the call is not \
                 expanded"
            )))
        }
    };
    if string_body {
        let search_path = function_search_path(function);
        let mut qualify = QualifyStringBodyTables {
            db,
            search_path: &search_path,
            failed: None,
        };
        let _ = VisitMut::visit(&mut body, &mut qualify);
        if let Some(reason) = qualify.failed {
            return Some(refused(format!(
                "The body of '{function_name}' {reason}, so the call is not expanded"
            )));
        }
    }

    let security = function.security_mode();
    if matches!(security, FunctionSecurity::Definer)
        && body_reads_effective_user(
            &function
                .body()
                .map_or_else(|| body.to_string(), str::to_string),
        )
    {
        return Some(refused(format!(
            "Function '{function_name}' is SECURITY DEFINER and its body reads \
             current_user, whose value is the owner's for every caller"
        )));
    }

    let mut scan = BodyScan::default();
    let _ = body.visit(&mut scan);
    if let Some(shape) = scan.unmodeled_relation {
        return Some(refused(format!(
            "The body of '{function_name}' reads {shape}, a relation shape the \
             expansion does not model"
        )));
    }

    // Declared argument names, in position order, as PostgreSQL stores them.
    let named_args: Vec<(usize, String)> = function
        .stored_argument_names(db)
        .enumerate()
        .filter_map(|(index, name)| name.map(|name| (index, name.into_owned())))
        .collect();

    // Q6: a bare body name matching both an argument and a column of a table in
    // scope resolves to the column, silently, so the clause would compare the
    // column to itself and admit every row.
    for (_, stored_arg) in &named_args {
        let occurs_bare = scan
            .bare_idents
            .iter()
            .any(|ident| stored_ident_name(ident).as_ref() == stored_arg);
        if !occurs_bare {
            continue;
        }
        if let Some(table) = scan
            .tables
            .iter()
            .find(|table| table_has_column(db, table, stored_arg))
        {
            return Some(refused(format!(
                "The body of '{function_name}' reads '{stored_arg}', which is both its \
                 argument and a column of '{table}', so PostgreSQL reads the column and \
                 the shadowed argument is silently unused"
            )));
        }
    }

    let mut reads_bypass_rls = false;
    if matches!(security, FunctionSecurity::Definer) && !scan.tables.is_empty() {
        let Ok(function_owner) = function.owner(db) else {
            return Some(refused(format!(
                "The owner of '{function_name}' cannot be read, so whether its reads \
                 bypass row level security cannot be known"
            )));
        };
        for spelling in &scan.tables {
            let Some(table) = lookup_table(db, spelling) else {
                return Some(refused(format!(
                    "The body of '{function_name}' reads '{spelling}', which the schema \
                     does not declare"
                )));
            };
            if table.has_forced_row_level_security(db) != Ok(false) {
                return Some(refused(format!(
                    "'{spelling}' has FORCE ROW LEVEL SECURITY, so the definer's own \
                     read of it is filtered and the self-referential shape recurses at \
                     runtime"
                )));
            }
            let Ok(table_owner) = table.owner(db) else {
                return Some(refused(format!(
                    "The owner of '{spelling}' cannot be read, so whether \
                     '{function_name}' reads it unfiltered cannot be known"
                )));
            };
            let owners_match = owners_share_identity(db, function_owner, table_owner);
            if owners_match || owner_bypasses_rls(db, function_owner) {
                continue;
            }
            let owner = function_owner.unwrap_or("the schema principal");
            return Some(refused(format!(
                "Function '{function_name}' runs as {owner}, which does not provably \
                 read '{spelling}' unfiltered, so the rows its body counts cannot be \
                 known from the schema"
            )));
        }
        reads_bypass_rls = true;
    }

    // A column argument substitutes as the policy table's own reference, since a
    // policy expression resolves a bare column against its table and the body's
    // subqueries would otherwise capture the name. A qualifier one of the body's
    // relations claims cannot be spelled from inside, so it refuses.
    let outer_parts = qualifier_idents(table);
    let outer_stored = stored_relation_name(table);
    let capture_prone = call_args.iter().any(|arg| match arg {
        Expr::Identifier(_) => scan.scope_names.contains(&outer_stored),
        Expr::CompoundIdentifier(parts) => parts.first().is_some_and(|qualifier| {
            let qualifier = stored_ident_name(qualifier);
            scan.scope_names.iter().any(|name| *name == qualifier)
        }),
        Expr::Value(_) => false,
        // A computed argument carries the same hazards through its inner references.
        // A query-bearing one is left for the substitution loop's own refusal.
        wrapped => {
            !contains_query(wrapped) && {
                let columns = argument_columns(wrapped);
                (columns.has_bare_column && scan.scope_names.contains(&outer_stored))
                    || columns
                        .qualifiers
                        .iter()
                        .any(|qualifier| scan.scope_names.iter().any(|name| name == qualifier))
            }
        }
    });
    if capture_prone {
        return Some(refused(format!(
            "The body of '{function_name}' reads a relation named like the argument's \
             table, so the substituted reference would be captured by the body's own \
             scope"
        )));
    }
    let mut replacements: Vec<Expr> = Vec::with_capacity(call_args.len());
    for arg in &call_args {
        let replacement = match arg {
            Expr::Identifier(column) => {
                let mut parts = outer_parts.clone();
                parts.push(column.clone());
                Expr::CompoundIdentifier(parts)
            }
            Expr::CompoundIdentifier(_) | Expr::Value(_) => arg.clone(),
            wrapped => {
                let Some(qualified) = qualify_argument_columns(wrapped, &outer_parts) else {
                    return Some(refused(format!(
                        "Argument '{wrapped}' of '{function_name}' contains a subquery, \
                         whose scopes cannot be told apart from the policy's"
                    )));
                };
                Expr::Nested(Box::new(qualified))
            }
        };
        replacements.push(replacement);
    }

    let null_short_circuits = !matches!(
        function.null_input_behavior(),
        FunctionCalledOnNull::CalledOnNullInput
    );
    let mut presence_columns = Vec::new();
    let mut has_null_literal = false;
    if null_short_circuits {
        for arg in &call_args {
            if let Some(column) = call_argument_column(arg, table) {
                if !presence_columns.contains(&column) {
                    presence_columns.push(column);
                }
                continue;
            }
            match arg {
                Expr::Value(value) if matches!(value.value, Value::Null) => {
                    has_null_literal = true;
                }
                Expr::Value(value) if !matches!(value.value, Value::Placeholder(_)) => {}
                _ => {
                    return Some(refused(format!(
                        "Function '{function_name}' has a null input contract, but argument \
                         '{arg}' is not a column or literal whose nullability can be preserved"
                    )))
                }
            }
        }
    }

    let mut substituted = body;
    let mut rewrite = Substitute {
        replacements: &replacements,
        named_args: &named_args,
        function_terminal: &terminal,
        scope_names: &scan.scope_names,
        failed: None,
    };
    let _ = VisitMut::visit(&mut substituted, &mut rewrite);
    if let Some(reason) = rewrite.failed {
        return Some(refused(format!(
            "The body of '{function_name}' {reason}, so the call is not expanded"
        )));
    }
    if has_null_literal {
        substituted = Expr::Value(Value::Boolean(false).into());
        presence_columns.clear();
    }

    Some(Expansion::Body {
        function: function_name,
        identity: terminal,
        reads_bypass_rls,
        presence_columns,
        expr: Box::new(substituted),
    })
}

fn refused(reason: String) -> Expansion {
    Expansion::Refused { reason }
}

enum FunctionSearchPath {
    Missing,
    Static(Vec<String>),
    Invalid(&'static str),
}

fn object_name_part_ident(part: &ObjectNamePart) -> &Ident {
    match part {
        ObjectNamePart::Identifier(ident) => ident,
        ObjectNamePart::Function(function) => &function.name,
    }
}

fn static_search_path_entry(value: &Expr) -> Option<String> {
    match value {
        Expr::Identifier(ident) => {
            Some(stored_identifier(&ident.value, ident.quote_style.is_some()).into_owned())
        }
        Expr::Value(value) => {
            let Value::SingleQuotedString(value) = &value.value else {
                return None;
            };
            let value = value.trim();
            if value.contains(',') {
                return None;
            }
            let quoted = value.len() >= 2 && value.starts_with('"') && value.ends_with('"');
            let unquoted = unquote_identifier(value);
            let stored = stored_identifier(unquoted.as_ref(), quoted);
            (stored != "$user").then(|| stored.into_owned())
        }
        _ => None,
    }
}

fn function_search_path<F: FunctionLike>(function: &F) -> FunctionSearchPath {
    let Some(parameter) = function
        .configuration_parameters()
        .iter()
        .rev()
        .find(|parameter| {
            matches!(
                parameter.name.0.as_slice(),
                [part]
                    if stored_identifier(
                        object_name_part_ident(part).value.as_str(),
                        object_name_part_ident(part).quote_style.is_some(),
                    ) == "search_path"
            )
        })
    else {
        return FunctionSearchPath::Missing;
    };
    match &parameter.value {
        FunctionSetValue::Default => FunctionSearchPath::Invalid("uses DEFAULT"),
        FunctionSetValue::FromCurrent => FunctionSearchPath::Invalid("uses FROM CURRENT"),
        FunctionSetValue::Values(values) => {
            let mut path = Vec::with_capacity(values.len());
            for value in values {
                let Some(schema) = static_search_path_entry(value) else {
                    return FunctionSearchPath::Invalid(
                        "contains a value that is not a static schema identifier",
                    );
                };
                path.push(schema);
            }
            FunctionSearchPath::Static(path)
        }
    }
}

fn resolve_body_table<'db, DB: DatabaseLike>(
    db: &'db DB,
    name: &ObjectName,
    search_path: &[String],
) -> Result<Option<&'db DB::Table>, &'static str> {
    for implicit in ["pg_temp", "pg_catalog"] {
        if !search_path.iter().any(|schema| schema == implicit) {
            return Err(implicit);
        }
    }
    let [part] = name.0.as_slice() else {
        return Ok(None);
    };
    let ident = object_name_part_ident(part);
    let target = stored_identifier(&ident.value, ident.quote_style.is_some());
    for schema in search_path {
        if matches!(schema.as_str(), "pg_temp" | "pg_catalog") {
            return Err(if schema == "pg_temp" {
                "pg_temp"
            } else {
                "pg_catalog"
            });
        }
        let mut found = None;
        for table in db.tables() {
            let table_schema = table.stored_table_schema();
            if table.stored_table_name() != target
                || table_schema.as_deref().unwrap_or("public") != schema
            {
                continue;
            }
            if found.replace(table).is_some() {
                return Ok(None);
            }
        }
        if found.is_some() {
            return Ok(found);
        }
    }
    Ok(None)
}
fn declared_ident(value: &str, quoted: bool) -> Ident {
    if quoted {
        Ident::with_quote('"', value)
    } else {
        Ident::new(value)
    }
}

fn qualified_table_name<T: TableLike>(table: &T) -> ObjectName {
    let schema = declared_ident(
        table.table_schema().unwrap_or("public"),
        table.table_schema_is_quoted(),
    );
    let table = declared_ident(table.table_name(), table.table_name_is_quoted());
    ObjectName(vec![
        ObjectNamePart::Identifier(schema),
        ObjectNamePart::Identifier(table),
    ])
}

struct QualifyStringBodyTables<'db, 'path, DB: DatabaseLike> {
    db: &'db DB,
    search_path: &'path FunctionSearchPath,
    failed: Option<String>,
}

impl<DB: DatabaseLike> VisitorMut for QualifyStringBodyTables<'_, '_, DB> {
    type Break = ();

    fn pre_visit_table_factor(&mut self, table_factor: &mut TableFactor) -> ControlFlow<()> {
        let TableFactor::Table { name, .. } = table_factor else {
            return ControlFlow::Continue(());
        };
        if name.0.len() != 1 {
            return ControlFlow::Continue(());
        }
        let spelling = name.to_string();
        let table = match self.search_path {
            FunctionSearchPath::Missing => {
                self.failed = Some(format!(
                    "reads unqualified table '{spelling}' without a fixed search_path"
                ));
                return ControlFlow::Break(());
            }
            FunctionSearchPath::Invalid(reason) => {
                self.failed = Some(format!(
                    "reads unqualified table '{spelling}', but its search_path {reason}"
                ));
                return ControlFlow::Break(());
            }
            FunctionSearchPath::Static(path) => match resolve_body_table(self.db, name, path) {
                Ok(table) => table,
                Err(schema) => {
                    self.failed = Some(format!(
                        "reads unqualified table '{spelling}', which {schema} may shadow before \
                         its fixed search_path resolves it"
                    ));
                    return ControlFlow::Break(());
                }
            },
        };
        let Some(table) = table else {
            self.failed = Some(format!(
                "reads unqualified table '{spelling}', which its fixed search_path does not \
                 resolve to a declared table"
            ));
            return ControlFlow::Break(());
        };
        *name = qualified_table_name(table);
        ControlFlow::Continue(())
    }
}

/// The policy table's spelling as identifier parts, quoting preserved.
fn qualifier_idents(table: &str) -> Vec<Ident> {
    let Some(target) = crate::parser::names::parse_target(table) else {
        return Vec::new();
    };
    match target.schema() {
        Some(schema) => vec![
            declared_ident(schema, target.schema_is_quoted()),
            declared_ident(target.name(), target.name_is_quoted()),
        ],
        None => vec![declared_ident(target.name(), target.name_is_quoted())],
    }
}

/// The identifier shapes a computed argument carries, for the capture guard.
struct ArgumentColumns {
    /// A bare non-keyword identifier, which is the policy table's column.
    has_bare_column: bool,
    /// Stored first parts of qualified references, which a body scope may claim.
    qualifiers: Vec<String>,
}

fn argument_columns(expr: &Expr) -> ArgumentColumns {
    struct Collect(ArgumentColumns);
    impl Visitor for Collect {
        type Break = ();
        fn post_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
            match expr {
                Expr::Identifier(ident) => {
                    let keyword = ident.quote_style.is_none()
                        && crate::parser::names::is_current_user_keyword_name(&ident.value);
                    if !keyword {
                        self.0.has_bare_column = true;
                    }
                }
                Expr::CompoundIdentifier(parts) => {
                    if let Some(qualifier) = parts.first() {
                        self.0
                            .qualifiers
                            .push(stored_ident_name(qualifier).into_owned());
                    }
                }
                _ => {}
            }
            ControlFlow::Continue(())
        }
    }
    let mut collector = Collect(ArgumentColumns {
        has_bare_column: false,
        qualifiers: Vec::new(),
    });
    let _ = expr.visit(&mut collector);
    collector.0
}
/// Whether the computed argument's expression contains a subquery.
fn contains_query(expr: &Expr) -> bool {
    struct FindsQuery(bool);
    impl Visitor for FindsQuery {
        type Break = ();
        fn pre_visit_query(&mut self, _query: &sqlparser::ast::Query) -> ControlFlow<Self::Break> {
            self.0 = true;
            ControlFlow::Break(())
        }
    }
    let mut finder = FindsQuery(false);
    let _ = expr.visit(&mut finder);
    finder.0
}

/// Rewrite each bare column of a computed argument into the policy table's own
/// reference, the bare-argument arm's exact substitution, so the body's scopes
/// cannot capture it. An unquoted current-user keyword stays: qualifying it would
/// turn the keyword into a column read.
///
/// `None` when the expression contains a subquery, whose inner scopes cannot be
/// told apart from the caller's without re-implementing name resolution.
fn qualify_argument_columns(expr: &Expr, outer_parts: &[Ident]) -> Option<Expr> {
    struct Qualify<'a> {
        outer_parts: &'a [Ident],
    }
    impl VisitorMut for Qualify<'_> {
        type Break = ();
        fn post_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<()> {
            if let Expr::Identifier(ident) = &*expr {
                let keyword = ident.quote_style.is_none()
                    && crate::parser::names::is_current_user_keyword_name(&ident.value);
                if !keyword {
                    let mut parts = self.outer_parts.to_vec();
                    parts.push(ident.clone());
                    *expr = Expr::CompoundIdentifier(parts);
                }
            }
            ControlFlow::Continue(())
        }
    }
    if contains_query(expr) {
        return None;
    }
    let mut rewritten = expr.clone();
    let mut qualify = Qualify { outer_parts };
    let _ = VisitMut::visit(&mut rewritten, &mut qualify);
    Some(rewritten)
}

fn call_argument_column(arg: &Expr, table: &str) -> Option<ColumnName> {
    let column = match arg {
        Expr::Identifier(column) => column,
        Expr::CompoundIdentifier(parts) => {
            let (column, qualifiers) = parts.split_last()?;
            let expected = qualifier_idents(table);
            let exact = qualifiers.len() == expected.len()
                && qualifiers
                    .iter()
                    .zip(&expected)
                    .all(|(left, right)| stored_ident_name(left) == stored_ident_name(right));
            let terminal = qualifiers
                .first()
                .zip(expected.last())
                .is_some_and(|(left, right)| {
                    qualifiers.len() == 1 && stored_ident_name(left) == stored_ident_name(right)
                });
            if !exact && !terminal {
                return None;
            }
            column
        }
        _ => return None,
    };
    Some(ColumnName::from_stored(
        stored_ident_name(column).into_owned(),
    ))
}

/// Whether `call` names `declared`.
///
/// A declaration stored without a schema sits in the first schema on the search path, and
/// that is the schema a dump's qualified call spells, so the effective schema is compared
/// rather than the stored one. The registry canonicalizes an unqualified declaration by
/// the same search-path entry.
fn call_matches_declared<DB: DatabaseLike>(
    call: &ObjectName,
    declared: &DB::Function,
    db: &DB,
) -> bool {
    let mut call_parts = call.0.iter().rev().map(object_name_part_ident);
    let Some(call_name) = call_parts.next() else {
        return false;
    };
    if stored_ident_name(call_name) != declared.stored_name() {
        return false;
    }
    let Some(call_schema) = call_parts.next() else {
        return true;
    };
    let target = declared.target_name();
    let declared_schema = if let Some(schema) = target.schema() {
        stored_identifier(schema, target.schema_is_quoted())
    } else {
        let Some((schema, quoted)) = db.search_path().next() else {
            return false;
        };
        stored_identifier(schema, quoted)
    };
    stored_ident_name(call_schema) == declared_schema
}

fn owner_identity<DB: DatabaseLike>(db: &DB, owner: &str) -> String {
    db.role(owner).map_or_else(
        || {
            let owner = owner.trim();
            let quoted = owner.len() >= 2 && owner.starts_with('"') && owner.ends_with('"');
            stored_identifier(unquote_identifier(owner).as_ref(), quoted).into_owned()
        },
        |role| role.stored_name().into_owned(),
    )
}

fn owners_share_identity<DB: DatabaseLike>(
    db: &DB,
    function_owner: Option<&str>,
    table_owner: Option<&str>,
) -> bool {
    match (function_owner, table_owner) {
        (None, None) => true,
        (Some(function_owner), Some(table_owner)) => {
            owner_identity(db, function_owner) == owner_identity(db, table_owner)
        }
        _ => false,
    }
}

fn owner_bypasses_rls<DB: DatabaseLike>(db: &DB, owner: Option<&str>) -> bool {
    owner
        .and_then(|owner| db.role(owner))
        .is_some_and(RoleLike::can_bypass_rls)
}

/// Everything the substitution and the ownership gate need to know about the
/// body: the tables it reads, every name a bare or qualified reference may
/// resolve against, and every bare identifier.
#[derive(Default)]
struct BodyScan {
    /// Relation spellings the body reads, for the ownership gate.
    tables: Vec<String>,
    /// Normalized table and alias names in scope, which claim a qualifier.
    scope_names: Vec<String>,
    /// Every bare identifier, for the shadowed-argument guard.
    bare_idents: Vec<Ident>,
    /// A table factor the scan does not model, which refuses the expansion.
    unmodeled_relation: Option<&'static str>,
}

impl Visitor for BodyScan {
    type Break = ();

    fn pre_visit_table_factor(&mut self, table_factor: &TableFactor) -> ControlFlow<()> {
        match table_factor {
            TableFactor::Table { name, alias, .. } => {
                let spelling = name.to_string();
                // An alias hides the table's own name for that scope, so only
                // the name a qualifier can actually resolve against is held.
                match alias {
                    Some(alias) => self
                        .scope_names
                        .push(stored_ident_name(&alias.name).into_owned()),
                    None => self.scope_names.push(stored_relation_name(&spelling)),
                }
                self.tables.push(spelling);
            }
            TableFactor::Derived { alias, .. } => {
                if let Some(alias) = alias {
                    self.scope_names
                        .push(stored_ident_name(&alias.name).into_owned());
                }
            }
            _ => self.unmodeled_relation = Some("a joined or function-valued relation"),
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
        if let Expr::Identifier(ident) = expr {
            self.bare_idents.push(ident.clone());
        }
        ControlFlow::Continue(())
    }
}

/// Rewrites parameter references to the call-site arguments, bottom up so a
/// substituted argument is never rewritten again.
struct Substitute<'a> {
    /// Per-position call arguments, already spelled for the body's scope.
    replacements: &'a [Expr],
    /// Declared argument positions by stored name.
    named_args: &'a [(usize, String)],
    /// Normalized terminal name of the function, which qualifies its own
    /// arguments in the `f.arg` spelling.
    function_terminal: &'a str,
    /// Normalized names a qualifier resolves against before the function name.
    scope_names: &'a [String],
    failed: Option<&'static str>,
}

impl Substitute<'_> {
    fn argument_for(&self, stored: &str) -> Option<&Expr> {
        self.named_args
            .iter()
            .find(|(_, name)| name == stored)
            .and_then(|(index, _)| self.replacements.get(*index))
    }
}

impl VisitorMut for Substitute<'_> {
    type Break = ();

    fn post_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<()> {
        let replacement = match &*expr {
            Expr::Value(value) => {
                if let Value::Placeholder(placeholder) = &value.value {
                    if let Some(argument) = placeholder
                        .strip_prefix('$')
                        .and_then(|index| index.parse::<usize>().ok())
                        .and_then(|index| index.checked_sub(1))
                        .and_then(|index| self.replacements.get(index))
                    {
                        Some(argument.clone())
                    } else {
                        self.failed = Some("names a positional parameter the declaration lacks");
                        None
                    }
                } else {
                    None
                }
            }
            Expr::Identifier(ident) => self
                .argument_for(stored_ident_name(ident).as_ref())
                .cloned(),
            Expr::CompoundIdentifier(parts) => match parts.as_slice() {
                [qualifier, name] => {
                    let qualifier = stored_ident_name(qualifier);
                    if self.scope_names.iter().any(|held| *held == qualifier) {
                        None
                    } else if qualifier == self.function_terminal {
                        self.argument_for(stored_ident_name(name).as_ref()).cloned()
                    } else {
                        None
                    }
                }
                _ => None,
            },
            _ => None,
        };
        if let Some(replacement) = replacement {
            *expr = replacement;
        }
        ControlFlow::Continue(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::expr::parse_expr_for_tests as parse_expr;

    fn outer() -> Vec<Ident> {
        qualifier_idents("docs")
    }

    #[test]
    fn a_bare_column_in_a_computed_argument_qualifies() {
        let rewritten = qualify_argument_columns(&parse_expr("coalesce(level, 0)"), &outer())
            .expect("no subquery, so the rewrite succeeds");
        assert_eq!(rewritten.to_string(), "coalesce(docs.level, 0)");
    }

    #[test]
    fn a_current_user_keyword_in_a_computed_argument_stays() {
        // `current_user` parses as a no-argument function and never reaches the
        // rewrite. `current_role` parses as a bare identifier, so it is the spelling
        // the keyword skip protects.
        for spelling in ["current_user::text", "current_role::text"] {
            let rewritten = qualify_argument_columns(&parse_expr(spelling), &outer())
                .expect("no subquery, so the rewrite succeeds");
            assert_eq!(
                rewritten.to_string().to_lowercase(),
                spelling.to_lowercase(),
                "`{spelling}` must stay unqualified"
            );
        }
    }

    #[test]
    fn a_quoted_current_user_column_still_qualifies() {
        let rewritten = qualify_argument_columns(&parse_expr("\"current_user\"::text"), &outer())
            .expect("no subquery, so the rewrite succeeds");
        assert_eq!(rewritten.to_string(), "docs.\"current_user\"::TEXT");
    }

    #[test]
    fn a_subquery_in_a_computed_argument_refuses() {
        assert_eq!(
            qualify_argument_columns(&parse_expr("(SELECT max(level) FROM other)"), &outer()),
            None,
            "a subquery's inner scopes cannot be told apart from the caller's"
        );
    }
}
