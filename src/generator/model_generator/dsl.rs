use super::*;

pub(super) fn render_dsl(
    types: &[TypePlan],
    conditions: &BTreeMap<ConditionName, ConditionSpec>,
) -> String {
    let mut dsl = String::new();
    let _ = writeln!(dsl, "model");
    let _ = writeln!(dsl, "  schema {OPENFGA_SCHEMA_VERSION}");

    for t in types {
        let _ = writeln!(dsl);
        let _ = writeln!(dsl, "type {}", t.type_name);

        if t.direct_relations.is_empty() && t.computed_relations.is_empty() {
            continue;
        }

        let _ = writeln!(dsl, "  relations");
        for (relation, subjects) in &t.direct_relations {
            let _ = writeln!(dsl, "    define {relation}: {}", format_subjects(subjects));
        }
        for (relation, expr) in &t.computed_relations {
            let _ = writeln!(dsl, "    define {relation}: {}", expr_to_dsl(expr, None));
        }
    }

    // Conditions follow the types, which is the order the DSL grammar accepts.
    for (name, spec) in conditions {
        let parameters = spec
            .parameters
            .iter()
            .map(|(parameter, kind)| format!("{parameter}: {}", dsl_parameter_type(kind)))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(dsl);
        let _ = writeln!(dsl, "condition {name}({parameters}) {{");
        let _ = writeln!(dsl, "  {}", spec.expression);
        let _ = writeln!(dsl, "}}");
    }

    dsl
}

/// The DSL spells a parameter type in lower case, where the JSON names it
/// `TYPE_NAME_TIMESTAMP`, and spells a list's element type inside angle brackets.
fn dsl_parameter_type(kind: &ConditionParameter) -> String {
    fn bare(type_name: &str) -> String {
        type_name
            .strip_prefix("TYPE_NAME_")
            .unwrap_or(type_name)
            .to_lowercase()
    }
    match kind {
        ConditionParameter::Scalar(type_name) => bare(type_name),
        ConditionParameter::Clock(_) => bare(TIMESTAMP_PARAMETER_TYPE),
        ConditionParameter::ListOf(element) => format!("list<{}>", bare(element)),
        ConditionParameter::MapOf(element) => format!("map<{}>", bare(element)),
    }
}

fn format_subjects(subjects: &[DirectSubject]) -> String {
    let parts = subjects
        .iter()
        .map(DirectSubject::dsl_text)
        .collect::<Vec<_>>();
    format!("[{}]", parts.join(", "))
}

/// Render one userset. The DSL admits a single operator per nesting level, so a
/// child of another kind is parenthesized. `parent` is the operator this expression
/// sits under, or `None` at the top of a definition.
pub(super) fn expr_to_dsl(expr: &UsersetExpr, parent: Option<&str>) -> String {
    const ATOM: &str = "";
    let (operator, parts) = match expr {
        UsersetExpr::Computed(name) => return name.clone().to_string(),
        UsersetExpr::TupleToUserset { tupleset, computed } => {
            return format!("{computed} from {tupleset}")
        }
        UsersetExpr::Union(children) => (
            "or",
            children
                .iter()
                .map(|child| expr_to_dsl(child, Some("or")))
                .collect::<Vec<_>>(),
        ),
        UsersetExpr::Intersection(children) => (
            "and",
            children
                .iter()
                .map(|child| expr_to_dsl(child, Some("and")))
                .collect::<Vec<_>>(),
        ),
        // `but not` takes exactly two operands and never chains, so both sides are
        // rendered as if they sat under no operator of their own.
        UsersetExpr::Exclusion { base, subtract } => (
            "but not",
            vec![
                expr_to_dsl(base, Some(ATOM)),
                expr_to_dsl(subtract, Some(ATOM)),
            ],
        ),
    };

    let rendered = parts.join(&format!(" {operator} "));
    if parent.is_some_and(|parent| parent != operator) {
        format!("({rendered})")
    } else {
        rendered
    }
}
