#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use core::fmt::Write;

use crate::classifier::patterns::{
    apply_threshold, AbacAnd, ArrayMembership, AttributeCondition, BooleanFlag,
    CallerScalarEqualsConstant, CallerScalarInConstantList, CallerScalarUnequalsConstant,
    ClassifiedExpr, ClassifiedPolicy, Composite, ConfidenceLevel, ConstantBool,
    ConstantInCallerSet, DeclaredHelper, DirectOwnership, ExcludedSet, ExistsMembership,
    ExpandedFunction, FallbackScalarEqualsConstant, FallbackScalarInConstantList,
    FallbackScalarUnequalsConstant, FlaggedRow, JsonbFieldOwnership, MembershipExclusion,
    MembershipInCallerSet, MembershipOnRequestValues, NumericThreshold, OwnerExpression,
    ParentInheritance, PolicyMode, ReferringRows, RequestValueAbsent, RequestValueInHelperSet,
    RoleNameInList, RowInHelperPairs, RowValueEqualsCallerScalar, RowValueInCallerSet,
    UnclassifiedExpr, UncorrelatedMembership,
};
use crate::generator::tuple_generator::{render_attribute_literal, render_attribute_test};
use crate::types::TranslationNote;

/// Remove Markdown table control characters and escape pipes.
fn md_escape(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .replace('|', r"\|")
}

/// Build a report from the unfiltered policies, listing only clauses or arms the threshold drops.
pub(crate) fn build_report(
    notes: &[TranslationNote],
    policies: &[ClassifiedPolicy],
    min_confidence: ConfidenceLevel,
) -> String {
    let mut report = String::new();

    let _ = writeln!(report, "# rls2fga Translation Report");
    let _ = writeln!(report);

    // Confidence table
    let _ = writeln!(report, "## Confidence Summary");
    let _ = writeln!(report);
    let _ = writeln!(report, "| Policy | Pattern | Confidence | Notes |");
    let _ = writeln!(report, "|--------|---------|------------|-------|");

    for cp in policies {
        let notes_cell = notes_for_policy(notes, cp.name());
        let using = cp.using_classification.as_ref();
        let with_check = cp.with_check_classification.as_ref();
        // The notes belong to the policy, so the second row does not repeat them.
        let check_notes = if using.is_some() { "" } else { &notes_cell };

        let mut wrote_row = false;
        wrote_row |= write_classification_row(&mut report, cp.name(), "USING", using, &notes_cell);
        wrote_row |= write_classification_row(
            &mut report,
            cp.name(),
            "WITH CHECK",
            with_check,
            check_notes,
        );
        if !wrote_row {
            let _ = writeln!(
                report,
                "| {} | N/A | N/A | {} |",
                md_escape(cp.name()),
                md_escape(&notes_cell)
            );
        }
    }

    write_dropped_section(&mut report, policies, min_confidence);

    if !notes.is_empty() {
        let _ = writeln!(report);
        let _ = writeln!(report, "## Notes");
        let _ = writeln!(report);

        for note in notes {
            let _ = writeln!(
                report,
                "- **[{}]** {}: {}",
                note.severity(),
                note.subject(),
                note
            );
        }
    }

    report
}

/// Enumerate what the threshold excluded from the model and tuple output.
///
/// The partition is the model's own (`apply_threshold`), so a permissive `OR` whose
/// strong arms survive lists only its dropped arms, never the clause whole.
fn write_dropped_section(
    report: &mut String,
    policies: &[ClassifiedPolicy],
    min_confidence: ConfidenceLevel,
) {
    let mut dropped: Vec<(&ClassifiedPolicy, &str, ClassifiedExpr, bool)> = Vec::new();
    for cp in policies {
        let permissive = cp.mode() == PolicyMode::Permissive;
        for (label, classification) in [
            ("USING", cp.using_classification.as_ref()),
            ("WITH CHECK", cp.with_check_classification.as_ref()),
        ] {
            let (kept, lost) = apply_threshold(classification, min_confidence, permissive);
            let partial = kept.is_some();
            dropped.extend(lost.into_iter().map(|expr| (cp, label, expr, partial)));
        }
    }

    if dropped.is_empty() {
        return;
    }

    let _ = writeln!(report);
    let _ = writeln!(report, "## Dropped Below Confidence {min_confidence}");
    let _ = writeln!(report);
    let _ = writeln!(
        report,
        "A dropped PERMISSIVE clause or arm grants nothing, a dropped RESTRICTIVE clause \
         or arm becomes `no_access`, and only listed `OR` arms are excluded from the model \
         and tuple output."
    );
    let _ = writeln!(report);

    for (cp, label, classification, partial) in dropped {
        let survives = if partial { ", other arms survive" } else { "" };
        let _ = writeln!(
            report,
            "- `{}` ({label}, {} {}, confidence {}{survives}): {}",
            md_escape(cp.name()),
            cp.mode(),
            cp.command(),
            classification.confidence,
            md_escape(&format_pattern(&classification.pattern))
        );
    }
}

fn write_classification_row(
    report: &mut String,
    policy_name: &str,
    clause_label: &str,
    classification: Option<&ClassifiedExpr>,
    notes: &str,
) -> bool {
    let Some(classification) = classification else {
        return false;
    };
    let _ = writeln!(
        report,
        "| {} ({}) | {} | {} | {} |",
        md_escape(policy_name),
        clause_label,
        md_escape(&format_pattern(&classification.pattern)),
        classification.confidence,
        md_escape(notes)
    );
    true
}

/// The parameter the first source of a fallback read carries, which a display names the
/// value by.
fn fallback_parameter(first: &crate::types::FallbackStep) -> String {
    first.parameter.clone()
}

/// The call `call` spelled as written, followed by each label it is read at.
fn helper_call_text(call: &crate::classifier::patterns::HelperCall) -> String {
    let mut text = format!("{}({})", call.function, call.arguments.join(", "));
    if !call.labels.is_empty() {
        let _ = write!(text, " at {}", call.labels.join(", "));
    }
    text
}

/// The end of `edges` naming each edge's parent, `table.column` for each of its columns.
fn edge_parent(edges: &crate::classifier::patterns::TreeEdges) -> String {
    let columns: Vec<String> = edges
        .parent_columns
        .iter()
        .map(|column| format!("{}.{column}", edges.table))
        .collect();
    columns.join(" and ")
}

fn format_pattern(pattern: &crate::classifier::patterns::PatternClass) -> String {
    use crate::classifier::patterns::PatternClass;
    match pattern {
        PatternClass::P1NumericThreshold(NumericThreshold {
            operator,
            threshold,
            ..
        }) => {
            let op = match operator {
                crate::classifier::patterns::ThresholdOperator::Gte => ">=",
                crate::classifier::patterns::ThresholdOperator::Gt => ">",
            };
            format!("P1 (threshold {op} {threshold})")
        }
        PatternClass::P2RoleNameInList(RoleNameInList { role_names, .. }) => {
            format!("P2 (roles: {})", role_names.join(", "))
        }
        PatternClass::P3DirectOwnership(DirectOwnership { column }) => {
            format!("P3 ({column} = user)")
        }
        PatternClass::P11ArrayMembership(ArrayMembership { column }) => {
            format!("P11 (user in {column})")
        }
        PatternClass::P12JsonbFieldOwnership(JsonbFieldOwnership { column, path }) => {
            format!("P12 ({column} ->> {} = user)", path.join(" -> "))
        }
        PatternClass::P26OwnerExpression(OwnerExpression { expression, .. }) => {
            format!("P26 ({expression} = user)")
        }
        PatternClass::P4ExistsMembership(ExistsMembership { join_table, .. }) => {
            format!("P4 (EXISTS {join_table})")
        }
        PatternClass::P32MembershipOnRequestValues(MembershipOnRequestValues {
            join_table,
            compared,
            ..
        }) => {
            let columns: Vec<&str> = compared
                .iter()
                .map(|compared| compared.value_column.as_str())
                .collect();
            format!(
                "P32 (EXISTS {join_table} on request values in {})",
                columns.join(", ")
            )
        }
        PatternClass::P19IndirectMembership(membership) => {
            format!("P19 (membership through {})", membership.link_table)
        }
        PatternClass::P20DeclaredHelper(DeclaredHelper { column, call }) => {
            format!("P20 ({column} in {})", helper_call_text(call))
        }
        PatternClass::P30RowInHelperPairs(RowInHelperPairs {
            columns,
            literals,
            pairs,
        }) => {
            let mut operands: Vec<(usize, String)> = columns
                .iter()
                .map(|(at, column)| (*at, column.as_str().to_string()))
                .chain(
                    literals
                        .iter()
                        .filter_map(|(at, value)| Some((*at, render_attribute_literal(value)?))),
                )
                .collect();
            operands.sort_unstable_by_key(|(at, _)| *at);
            let operands: Vec<String> = operands.into_iter().map(|(_, operand)| operand).collect();
            format!(
                "P30 (({}) in {}({}))",
                operands.join(", "),
                pairs.function,
                pairs.arguments.join(", ")
            )
        }
        PatternClass::P27RequestValueInHelperSet(RequestValueInHelperSet {
            source,
            function,
            arguments,
            ..
        }) => {
            format!(
                "P27 (caller value {} in {function}({}))",
                source.request_parameter(),
                arguments.join(", ")
            )
        }
        PatternClass::P28RequestValueAbsent(RequestValueAbsent { source, negated }) => {
            let state = if *negated { "carried" } else { "absent" };
            format!("P28 (caller value {} {state})", source.request_parameter())
        }
        PatternClass::P13UncorrelatedMembership(UncorrelatedMembership {
            member_table, ..
        }) => {
            format!("P13 (member of {member_table}, any row)")
        }
        PatternClass::P5ParentInheritance(ParentInheritance { parent_table, .. }) => {
            format!("P5 (inherits from {parent_table})")
        }
        PatternClass::P31ReferringRows(ReferringRows {
            referring_table, ..
        }) => {
            format!("P31 (named by readable rows of {referring_table})")
        }
        PatternClass::ExpandedFunction(ExpandedFunction {
            function, inner, ..
        }) => {
            format!("{} via {function}()", format_pattern(&inner.pattern))
        }
        PatternClass::P6BooleanFlag(BooleanFlag { column, .. }) => format!("P6 ({column})"),
        PatternClass::P7AbacAnd(AbacAnd { attribute_part, .. }) => {
            format!("P7 (ABAC: {attribute_part})")
        }
        PatternClass::P8Composite(Composite { op, parts }) => {
            let mut rendered = format!("P8 ({op:?} of {} parts", parts.len());
            let grade = parts.iter().map(|part| part.confidence).min();
            if let Some(grade) = grade.filter(|grade| *grade < ConfidenceLevel::A) {
                let mut deciders = Vec::new();
                grade_deciders(parts, grade, &mut deciders);
                let _ = write!(rendered, ", graded {grade}");
                for (at, decider) in deciders.into_iter().enumerate() {
                    let joiner = if at == 0 { "" } else { " and" };
                    let _ = write!(rendered, "{joiner} by {}", format_pattern(decider));
                }
            }
            rendered.push(')');
            rendered
        }
        PatternClass::P9AttributeCondition(AttributeCondition {
            column,
            value_description,
            predicate,
            ..
        }) => match predicate
            .as_ref()
            .and_then(|predicate| render_attribute_test(&predicate.test))
        {
            Some(test) => format!("P9 ({column} {test})"),
            None => format!("P9 ({column} = {value_description})"),
        },
        PatternClass::P10ConstantBool(ConstantBool { value }) => {
            format!("P10 (constant {value})")
        }
        PatternClass::P18MembershipInCallerSet(MembershipInCallerSet {
            membership:
                ExistsMembership {
                    join_table,
                    user_column,
                    ..
                },
            source,
            ..
        }) => format!(
            "P18 ({join_table}.{user_column} in caller set {})",
            source.request_parameter()
        ),
        PatternClass::P14RowValueInCallerSet(RowValueInCallerSet { column, source, .. }) => {
            format!(
                "P14 ({column} in caller set {})",
                source.request_parameter()
            )
        }
        PatternClass::P15RowValueEqualsCallerScalar(RowValueEqualsCallerScalar {
            column,
            source,
        }) => {
            format!(
                "P15 ({column} = caller value {})",
                source.request_parameter()
            )
        }
        PatternClass::P16ConstantInCallerSet(ConstantInCallerSet { value, source, .. }) => {
            format!(
                "P16 ('{value}' in caller set {})",
                source.request_parameter()
            )
        }
        PatternClass::P17CallerScalarEqualsConstant(CallerScalarEqualsConstant {
            value,
            source,
        }) => {
            format!(
                "P17 (caller value {} = '{value}')",
                source.request_parameter()
            )
        }
        PatternClass::P21CallerScalarUnequalsConstant(CallerScalarUnequalsConstant {
            value,
            source,
        }) => {
            format!(
                "P21 (caller value {} <> '{value}')",
                source.request_parameter()
            )
        }
        PatternClass::P22CallerScalarInConstantList(CallerScalarInConstantList {
            values,
            negated,
            source,
        }) => {
            let negation = if *negated { "NOT " } else { "" };
            let listed = values
                .iter()
                .map(|value| format!("'{value}'"))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "P22 (caller value {} {}IN ({listed}))",
                source.request_parameter(),
                negation
            )
        }
        PatternClass::P23FallbackScalarEqualsConstant(FallbackScalarEqualsConstant {
            value,
            first,
            ..
        }) => {
            let parameter = fallback_parameter(first);
            format!("P23 (fallback value {parameter} = '{value}')")
        }
        PatternClass::P24FallbackScalarUnequalsConstant(FallbackScalarUnequalsConstant {
            value,
            first,
            ..
        }) => {
            let parameter = fallback_parameter(first);
            format!("P24 (fallback value {parameter} <> '{value}')")
        }
        PatternClass::P25FallbackScalarInConstantList(FallbackScalarInConstantList {
            values,
            negated,
            first,
            ..
        }) => {
            let negation = if *negated { "NOT " } else { "" };
            let listed = values
                .iter()
                .map(|value| format!("'{value}'"))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "P25 (fallback value {} {}IN ({listed}))",
                fallback_parameter(first),
                negation
            )
        }
        PatternClass::MembershipExclusion(MembershipExclusion { base, subtract }) => {
            let mut rendered = match base {
                Some(base) => {
                    let mut rendered = format_pattern(&base.pattern);
                    rendered.push_str(" but not ");
                    rendered
                }
                None => String::from("restrictive blocklist "),
            };
            for (at, excluded) in subtract.iter().enumerate() {
                if at != 0 {
                    rendered.push_str(", ");
                }
                let _ = match excluded {
                    ExcludedSet::Membership(membership) => {
                        write!(rendered, "{}", membership.join_table)
                    }
                    ExcludedSet::Helper(DeclaredHelper { column, call }) => {
                        write!(rendered, "{column} in {}", helper_call_text(call))
                    }
                    ExcludedSet::Flag(flag) => {
                        write!(rendered, "{}", format_pattern(&flag.pattern))
                    }
                };
            }
            rendered
        }
        PatternClass::P29FlaggedRow(FlaggedRow {
            column,
            table,
            edges,
            steps,
            ..
        }) => {
            let mut rendered = format!("P29 ({table} flagged at {column}");
            for step in steps {
                let _ = write!(rendered, " one edge up through {}", edge_parent(step));
            }
            if !edges.is_empty() {
                rendered.push_str(" or above it through ");
                for (at, edge) in edges.iter().enumerate() {
                    if at != 0 {
                        rendered.push_str(", ");
                    }
                    rendered.push_str(&edge_parent(edge));
                }
            }
            rendered.push(')');
            rendered
        }
        PatternClass::Unknown(UnclassifiedExpr { reason, .. }) => format!("Unknown: {reason}"),
    }
}

/// The parts of a composite graded `grade`, reached through the nested composites that
/// carry the same grade, so a chain of conjunctions names the part itself.
fn grade_deciders<'p>(
    parts: &'p [ClassifiedExpr],
    grade: ConfidenceLevel,
    deciders: &mut Vec<&'p crate::classifier::patterns::PatternClass>,
) {
    use crate::classifier::patterns::PatternClass;
    for part in parts.iter().filter(|part| part.confidence == grade) {
        match &part.pattern {
            PatternClass::P8Composite(Composite { parts, .. }) => {
                grade_deciders(parts, grade, deciders);
            }
            pattern => deciders.push(pattern),
        }
    }
}

/// The notes already computed for `policy_name`, rendered for one table cell.
///
/// The report is handed the notes, so the cell reads them rather than deriving a second
/// wording per pattern. A note is the policy's rather than the clause's, so the caller
/// puts it on the first row a policy writes and leaves the other blank.
fn notes_for_policy(notes: &[TranslationNote], policy_name: &str) -> String {
    notes
        .iter()
        .filter(|note| note.subject() == policy_name)
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(". ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::patterns::*;
    use crate::parser::sql_parser::{parse_schema, DatabaseLike, SessionSetting};
    use crate::test_support::{deployment, scalar};
    use crate::types::ColumnName;

    fn classified_policy(
        name: &str,
        using: Option<PatternClass>,
        with_check: Option<PatternClass>,
    ) -> ClassifiedPolicy {
        let sql = format!(
            "
CREATE TABLE docs(id uuid primary key);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY {name} ON docs USING (TRUE);
"
        );
        let db = parse_schema(&sql).expect("schema should parse");
        let policy = db.policies().next().expect("expected a policy");
        let mut result =
            ClassifiedPolicy::from_policy(policy, &db).expect("the policy is in its database");
        result.using_classification = using.map(|pattern| ClassifiedExpr {
            pattern,
            confidence: ConfidenceLevel::A,
        });
        result.with_check_classification = with_check.map(|pattern| ClassifiedExpr {
            pattern,
            confidence: ConfidenceLevel::C,
        });
        result
    }

    #[test]
    fn format_pattern_renders_gt_threshold_operator() {
        let pattern = PatternClass::P1NumericThreshold(NumericThreshold {
            resource_column: None,
            function_name: "role_level".to_string(),
            operator: ThresholdOperator::Gt,
            threshold: 5,
            command: PolicyCommand::Delete,
        });
        assert_eq!(format_pattern(&pattern), "P1 (threshold > 5)");
    }

    /// A referring-rows row names the table whose readable rows admit the guarded row.
    #[test]
    fn format_pattern_names_the_referring_table() {
        let pattern = PatternClass::P31ReferringRows(ReferringRows {
            referring_table: TableId::from_stored(None, "invitations".to_string()),
            referring_columns: vec![ColumnName::from_stored("organization_id")],
            inner_pattern: Box::new(ClassifiedExpr {
                pattern: PatternClass::P10ConstantBool(ConstantBool { value: true }),
                confidence: ConfidenceLevel::A,
            }),
        });
        assert_eq!(
            format_pattern(&pattern),
            "P31 (named by readable rows of public.invitations)"
        );
    }

    /// The row names the value the fallback read hands over by the first source's
    /// parameter, the constants in the order the list names them, the `NOT IN` spelling
    /// among them.
    #[test]
    fn format_pattern_names_the_fallback_value_by_its_first_source() {
        let first = crate::types::FallbackStep {
            setting_key: "request.jwt.claim.role".to_string(),
            parameter: "request_jwt_claim_role".to_string(),
            from_json_field: false,
            skips_empty: true,
            may_be_unset: true,
        };
        let rest = vec![crate::types::FallbackStep {
            setting_key: "request.jwt.claims".to_string(),
            parameter: "request_jwt_claims_role".to_string(),
            from_json_field: true,
            skips_empty: true,
            may_be_unset: false,
        }];
        for (pattern, rendered) in [
            (
                PatternClass::P23FallbackScalarEqualsConstant(FallbackScalarEqualsConstant {
                    value: "authenticated".to_string(),
                    first: first.clone(),
                    rest: rest.clone(),
                }),
                "P23 (fallback value request_jwt_claim_role = 'authenticated')".to_string(),
            ),
            (
                PatternClass::P24FallbackScalarUnequalsConstant(FallbackScalarUnequalsConstant {
                    value: "anonymous".to_string(),
                    first: first.clone(),
                    rest: rest.clone(),
                }),
                "P24 (fallback value request_jwt_claim_role <> 'anonymous')".to_string(),
            ),
            (
                PatternClass::P25FallbackScalarInConstantList(FallbackScalarInConstantList {
                    values: vec!["authenticated".to_string(), "anonymous".to_string()],
                    negated: false,
                    first: first.clone(),
                    rest: rest.clone(),
                }),
                "P25 (fallback value request_jwt_claim_role IN \
                 ('authenticated', 'anonymous'))"
                    .to_string(),
            ),
            (
                PatternClass::P25FallbackScalarInConstantList(FallbackScalarInConstantList {
                    values: vec!["authenticated".to_string(), "anonymous".to_string()],
                    negated: true,
                    first: first.clone(),
                    rest: rest.clone(),
                }),
                "P25 (fallback value request_jwt_claim_role NOT IN \
                 ('authenticated', 'anonymous'))"
                    .to_string(),
            ),
        ] {
            assert_eq!(format_pattern(&pattern), rendered);
        }
    }

    /// The cell reads the notes the translation computed, so a pattern the report has no
    /// prose for is not silently blank: it is blank because that policy drew no note.
    #[test]
    fn the_notes_cell_reads_the_notes_the_translation_computed() {
        let notes = vec![
            TranslationNote::RestrictiveAttributeRefused {
                policy: "docs_select".to_string(),
            },
            TranslationNote::AttributeNeedsRuntimeEnforcement {
                policy: "docs_select".to_string(),
                attribute: "status = 'published'".to_string(),
            },
            TranslationNote::RestrictiveAttributeRefused {
                policy: "other".to_string(),
            },
        ];

        let cell = notes_for_policy(&notes, "docs_select");
        assert!(
            cell.contains("RESTRICTIVE policy 'docs_select'"),
            "the policy's own notes reach its cell, got: {cell}"
        );
        assert!(
            cell.contains("status = 'published'"),
            "every note for the policy reaches the cell, got: {cell}"
        );
        assert!(
            !cell.contains("'other'"),
            "another policy's notes stay out, got: {cell}"
        );
        assert_eq!(
            notes_for_policy(&notes, "unmentioned"),
            "",
            "a policy nothing was said about gets an empty cell"
        );
    }

    #[test]
    fn build_report_renders_using_with_check_na_and_notes() {
        let notes = vec![TranslationNote::RestrictiveAttributeRefused {
            policy: "docs_select".to_string(),
        }];

        let policies = vec![
            classified_policy(
                "docs_select",
                Some(PatternClass::P3DirectOwnership(DirectOwnership {
                    column: ColumnName::from_stored("owner_id"),
                })),
                Some(PatternClass::P9AttributeCondition(AttributeCondition {
                    column: ColumnName::from_stored("status"),
                    value_description: "'published'".to_string(),
                    predicate: None,
                    request_predicate: None,
                })),
            ),
            classified_policy("docs_noop", None, None),
        ];

        let report = build_report(&notes, &policies, ConfidenceLevel::D);
        assert!(report.contains("docs_select (USING)"));
        assert!(report.contains("docs_select (WITH CHECK)"));
        assert!(report.contains("| docs_noop | N/A | N/A |  |"));
        assert!(report.contains("## Notes"));
        assert!(report.contains(
            "**[Unhandled]** docs_select: RESTRICTIVE policy 'docs_select' guards on an \
             attribute the model cannot express, so the command is denied"
        ));

        // The note reaches the policy's first row and is not repeated on its second, since
        // a note is the policy's rather than the clause's.
        let using_row = report
            .lines()
            .find(|line| line.contains("docs_select (USING)"))
            .expect("the USING row is written");
        let check_row = report
            .lines()
            .find(|line| line.contains("docs_select (WITH CHECK)"))
            .expect("the WITH CHECK row is written");
        assert!(
            using_row.contains("RESTRICTIVE policy 'docs_select'"),
            "the note fills the first row's cell, got: {using_row}"
        );
        assert!(
            check_row.ends_with("|  |"),
            "the second row leaves the cell empty, got: {check_row}"
        );
    }

    /// A permissive OR mixing a strong arm with a weak one keeps the strong arm in the
    /// model, so the report must list only the weak arm as excluded, and say the rest
    /// survives. Claiming the whole clause is excluded tells a caller they have no
    /// coverage while owner access is enforced.
    #[test]
    fn a_surviving_or_arm_is_not_reported_as_excluded() {
        let sql = "
CREATE TABLE docs(id uuid PRIMARY KEY, owner_id TEXT, meta TEXT);
CREATE FUNCTION my_mystery(TEXT) RETURNS BOOLEAN LANGUAGE plpgsql STABLE AS $$ BEGIN RETURN NULL; END $$;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = current_user OR my_mystery(meta));
";
        let db = parse_schema(sql).expect("schema should parse");
        let registry = crate::classifier::function_registry::FunctionRegistry::new();
        let classified = crate::classifier::policy_classifier::classify_policies(
            &db,
            &registry,
            &crate::test_support::caller_deployment(),
        );
        let report = build_report(&[], &classified, ConfidenceLevel::B);
        let section = report
            .split("## Dropped Below")
            .nth(1)
            .expect("the dropped section exists");

        assert!(
            !section.contains("Or of 2 parts"),
            "the clause is not excluded whole, one arm survives:\n{report}"
        );
        assert!(
            section.contains("my_mystery"),
            "the excluded arm is named:\n{report}"
        );
        assert!(
            section.contains("other arms survive"),
            "a partial drop says the rest stays in the model:\n{report}"
        );
    }

    /// A clause below the bar with no surviving arm keeps its whole-clause entry.
    #[test]
    fn a_fully_dropped_clause_stays_reported() {
        let sql = "
CREATE TABLE docs(id uuid PRIMARY KEY, meta TEXT);
CREATE FUNCTION my_mystery(TEXT) RETURNS BOOLEAN LANGUAGE plpgsql STABLE AS $$ BEGIN RETURN NULL; END $$;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (my_mystery(meta));
";
        let db = parse_schema(sql).expect("schema should parse");
        let registry = crate::classifier::function_registry::FunctionRegistry::new();
        let classified = crate::classifier::policy_classifier::classify_policies(
            &db,
            &registry,
            &crate::test_support::caller_deployment(),
        );
        let report = build_report(&[], &classified, ConfidenceLevel::B);

        assert!(
            report.contains("## Dropped Below Confidence B"),
            "the section exists:\n{report}"
        );
        assert!(
            report.contains("my_mystery"),
            "the dropped clause is named:\n{report}"
        );
        assert!(
            !report.contains("other arms survive"),
            "nothing survives, so no partial wording:\n{report}"
        );
    }

    /// The report row for the USING clause `using`, where the deployment declares
    /// `settings`.
    fn using_row(settings: impl IntoIterator<Item = SessionSetting>, using: &str) -> String {
        let sql = format!(
            "
CREATE TABLE docs(id uuid PRIMARY KEY, owner_id TEXT, expires_at TIMESTAMPTZ, meta TEXT);
CREATE FUNCTION my_mystery(TEXT) RETURNS BOOLEAN LANGUAGE plpgsql STABLE AS $$ BEGIN RETURN NULL; END $$;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING ({using});
"
        );
        let db = parse_schema(&sql).expect("schema should parse");
        let registry = crate::classifier::function_registry::FunctionRegistry::new();
        let classified = crate::classifier::policy_classifier::classify_policies(
            &db,
            &registry,
            &deployment(settings),
        );
        let report = build_report(&[], &classified, ConfidenceLevel::B);
        report
            .lines()
            .find(|line| line.starts_with("| p (USING)"))
            .expect("the USING row is written")
            .to_string()
    }

    /// A composite takes the grade of its weakest part, so its row names the parts that
    /// set that grade, reaching through nested composites to the part itself. Without
    /// them the operator reads only how many parts there were.
    #[test]
    fn a_composite_row_names_the_parts_that_set_its_grade() {
        const INFINITE: &str =
            "Unknown: INTERVAL 'infinity' has no finite length, so it has no CEL duration";
        const OPAQUE: &str = "Unknown: Function 'my_mystery' is LANGUAGE plpgsql, and only a \
                              single-expression LANGUAGE sql body expands";
        for (using, rendered) in [
            (
                "owner_id = current_user AND expires_at > now() - interval 'infinity'",
                format!("P8 (And of 2 parts, graded D by {INFINITE})"),
            ),
            (
                "owner_id = current_user AND (meta = 'x' AND \
                 expires_at > now() - interval 'infinity')",
                format!("P8 (And of 2 parts, graded D by {INFINITE})"),
            ),
            (
                "expires_at > now() - interval 'infinity' AND my_mystery(meta)",
                format!("P8 (And of 2 parts, graded D by {INFINITE} and by {OPAQUE})"),
            ),
            (
                "owner_id = current_user OR my_mystery(meta)",
                format!("P8 (Or of 2 parts, graded D by {OPAQUE})"),
            ),
            (
                "owner_id = current_user AND meta = 'x'",
                "P8 (And of 2 parts, graded B by P9 (owner_id = 'app_user') and by P9 (meta = 'x'))"
                    .to_string(),
            ),
        ] {
            let row = using_row([], using);
            assert!(
                row.starts_with(&format!("| p (USING) | {rendered} |")),
                "`{using}` must render as `{rendered}`, got: {row}"
            );
        }
    }

    /// `<>` and `IN` against literals compare the request's value with constants the rule
    /// supplies, so the row names the constant and the list's negation.
    #[test]
    fn setting_comparisons_name_their_constants() {
        let settings = || [scalar("app.tier")];
        let row = using_row(settings(), "current_setting('app.tier', true) <> 'a'");
        assert_eq!(
            row,
            "| p (USING) | P21 (caller value app_tier <> 'a') | A |  |"
        );
        for (using, rendered) in [
            (
                "current_setting('app.tier', true) IN ('a', 'b')",
                "P22 (caller value app_tier IN ('a', 'b'))",
            ),
            (
                "current_setting('app.tier', true) NOT IN ('a', 'b')",
                "P22 (caller value app_tier NOT IN ('a', 'b'))",
            ),
        ] {
            let row = using_row(settings(), using);
            assert_eq!(
                row,
                format!("| p (USING) | {rendered} | A |  |"),
                "`{using}` got: {row}"
            );
        }
    }
}
