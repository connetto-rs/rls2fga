#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use core::fmt::Write;

use crate::classifier::patterns::{
    apply_threshold, AbacAnd, ArrayMembership, AttributeCondition, BooleanFlag,
    CallerScalarEqualsConstant, ClassifiedExpr, ClassifiedPolicy, Composite, ConfidenceLevel,
    ConstantBool, ConstantInCallerSet, DirectOwnership, ExistsMembership, ExpandedFunction,
    JsonbFieldOwnership, MembershipExclusion, MembershipInCallerSet, NumericThreshold,
    ParentInheritance, PolicyMode, RoleNameInList, RowValueEqualsCallerScalar, RowValueInCallerSet,
    UnclassifiedExpr, UncorrelatedMembership,
};
use crate::generator::tuple_generator::render_attribute_test;
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
        PatternClass::P4ExistsMembership(ExistsMembership { join_table, .. }) => {
            format!("P4 (EXISTS {join_table})")
        }
        PatternClass::P19IndirectMembership(membership) => {
            format!("P19 (membership through {})", membership.link_table)
        }
        PatternClass::P13UncorrelatedMembership(UncorrelatedMembership {
            member_table, ..
        }) => {
            format!("P13 (member of {member_table}, any row)")
        }
        PatternClass::P5ParentInheritance(ParentInheritance { parent_table, .. }) => {
            format!("P5 (inherits from {parent_table})")
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
            format!("P8 ({op:?} of {} parts)", parts.len())
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
        PatternClass::MembershipExclusion(MembershipExclusion { base, subtract }) => {
            let mut rendered = match base {
                Some(base) => {
                    let mut rendered = format_pattern(&base.pattern);
                    rendered.push_str(" but not ");
                    rendered
                }
                None => String::from("restrictive blocklist "),
            };
            for (at, membership) in subtract.iter().enumerate() {
                if at != 0 {
                    rendered.push_str(", ");
                }
                let _ = write!(rendered, "{}", membership.join_table);
            }
            rendered
        }
        PatternClass::Unknown(UnclassifiedExpr { reason, .. }) => format!("Unknown: {reason}"),
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
    use crate::parser::sql_parser::{parse_schema, DatabaseLike};
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
        let mut result = ClassifiedPolicy::from_policy(policy, &db);
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
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = current_user OR my_mystery(meta));
";
        let db = parse_schema(sql).expect("schema should parse");
        let registry = crate::classifier::function_registry::FunctionRegistry::new();
        let classified = crate::classifier::policy_classifier::classify_policies(&db, &registry);
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
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (my_mystery(meta));
";
        let db = parse_schema(sql).expect("schema should parse");
        let registry = crate::classifier::function_registry::FunctionRegistry::new();
        let classified = crate::classifier::policy_classifier::classify_policies(&db, &registry);
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
}
