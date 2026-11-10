//! The exact-support grammar, checked without a database.
//!
//! A generator that emitted shapes the translation refuses would measure the refusal path
//! rather than the translation, and every case it produced would pass for the wrong reason.
//! These tests are what keeps the grammar honest before any container starts.

use crate::support;

use crate::support::exact_support::{
    declared_key, every_case, Accessor, KeyLength, KeyType, Shape, CALLERS, PRECONDITIONS,
};

use rls2fga::generator::model_generator::GeneratorSettings;
use rls2fga::translator::Translation;
use rls2fga::types::identity::MAX_OBJECT_NAME_CHARS;
use rls2fga::types::{
    ActionAnswer, ActionStatement, ConfidenceLevel, NoteSeverity, TranslationNote,
};

/// Plan one generated schema at the threshold the parity runner uses.
fn plan(schema: &str) -> Translation {
    let (classified, db, registry) = support::classify_sql_with_settings(schema, [declared_key()]);
    Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .expect("a case the grammar admits has to plan")
}

#[test]
fn the_exact_support_grammar_generates_only_translatable_policies() {
    for case in every_case() {
        let planned = plan(&case.schema);
        let unhandled: Vec<String> = planned
            .notes()
            .iter()
            .filter(|note| note.severity() == NoteSeverity::Unhandled)
            .map(ToString::to_string)
            .collect();
        assert!(
            unhandled.is_empty(),
            "{}: the grammar admits a shape nobody classified, so a case drawn from it \
             would measure the refusal path:\n{}",
            case.name,
            unhandled.join("\n")
        );
    }
}

#[test]
fn the_exact_support_grammar_admits_nothing_the_translation_calls_divergent() {
    for case in every_case() {
        let planned = plan(&case.schema);
        let diverging: Vec<String> = planned
            .notes()
            .iter()
            .filter(|note| note.severity().diverges_from_database())
            .map(ToString::to_string)
            .collect();
        // The grammar decides membership, so this is a claim about the translation: a shape
        // whose answer one row settles has nothing to disclose.
        assert!(
            diverging.is_empty(),
            "{}: the translation says it diverges on a shape the grammar admits:\n{}",
            case.name,
            diverging.join("\n")
        );
    }
}

#[test]
fn every_generated_case_reaches_a_judged_read() {
    for case in every_case() {
        let planned = plan(&case.schema);
        let answer = planned
            .action_relations()
            .iter()
            .find(|entry| {
                entry.type_name.as_str() == "guarded" && entry.statement == ActionStatement::Select
            })
            .map(|entry| &entry.answer);
        // Neither denied nor unrestricted: a case that granted everything or nothing would
        // agree with the database on the rows it happened to seed and prove nothing.
        assert!(
            matches!(answer, Some(ActionAnswer::Judged(_))),
            "{}: the read is {answer:?}, so no row is judged",
            case.name
        );
    }
}

#[test]
fn the_grammar_covers_every_axis_value_it_declares() {
    let cases = every_case();
    assert_eq!(
        cases.len(),
        Shape::ALL.len() * KeyType::ALL.len() * Accessor::ALL.len() * 2
            + KeyType::ALL.len() * KeyLength::ALL.len()
            + KeyType::ALL.len()
            + 2 * KeyType::ALL.len()
            + 2 * Accessor::ALL.len()
            + Accessor::ALL.len()
            + Accessor::ALL.len()
            + 2 * Accessor::ALL.len(),
        "the enumeration has to cover its axes, or a point goes unmeasured"
    );
    for barrier in ["barrier-on-request", "barrier-on-constant"] {
        assert!(
            cases.iter().any(|case| case.name.contains(barrier)),
            "no case narrows its grant with a {barrier}"
        );
    }
    assert!(
        cases.iter().any(|case| case.name.contains("every-command")),
        "no case declares a policy per command"
    );
    assert!(
        cases.iter().any(|case| case.name.contains("forced-owner")),
        "no case reads as the guarded table's owner"
    );
    for composition in ["two-policies", "or-clause"] {
        assert!(
            cases.iter().any(|case| case.name.contains(composition)),
            "no case composes its grants as {composition}"
        );
    }
    for depth in ["depth-two", "depth-three"] {
        assert!(
            cases.iter().any(|case| case.name.contains(depth)),
            "no case puts its rows at {depth}"
        );
    }
    for shape in ["self", "membership"] {
        assert!(
            cases.iter().any(|case| case.name.contains(shape)),
            "no case is shaped {shape}"
        );
    }
    assert!(
        cases
            .iter()
            .any(|case| case.name.contains("folded-collision")),
        "no case makes two tables fold onto one type name"
    );
    assert!(
        cases.iter().any(|case| case.name.contains("long-key")),
        "no case carries a key near the name cap"
    );
    for key in KeyType::ALL {
        for accessor in Accessor::ALL {
            assert!(
                cases.iter().any(|case| case.name.contains(match key {
                    KeyType::Text => "text",
                    KeyType::Integer => "int",
                    KeyType::Uuid => "uuid",
                }) && case.accessor == accessor),
                "no case pairs {key:?} with {accessor:?}"
            );
        }
    }
    assert_eq!(
        PRECONDITIONS, 8,
        "the documented preconditions are the class"
    );
}

#[test]
fn an_unset_caller_raises_only_where_the_spelling_says_so() {
    // PostgreSQL's rule, and the reason the parity runner needs told which caller raises.
    assert!(Accessor::BareSetting.raises_when_unset());
    assert!(Accessor::DeclaredFunction.raises_when_unset());
    assert!(!Accessor::MissingOkSetting.raises_when_unset());
}

#[test]
fn an_undeclared_request_key_falls_outside_the_class() {
    // Precondition 6 is a real boundary, not paperwork: without the declaration the same
    // schema refuses, and refusing is right, since nothing says which key carries the
    // caller. A grammar that admitted it would be measuring the refusal path.
    let case = every_case()
        .into_iter()
        .next()
        .expect("the grammar admits at least one case");
    let (classified, db, registry) = support::classify_sql(&case.schema, None);
    let planned = Translation::plan(
        classified,
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .expect("it still plans");
    let answer = planned
        .action_relations()
        .iter()
        .find(|entry| entry.statement == ActionStatement::Select)
        .map(|entry| &entry.answer);
    assert!(
        matches!(answer, Some(ActionAnswer::Denied)),
        "an undeclared key has to be refused rather than guessed, the read is {answer:?}"
    );
    // How the refusal is spelled depends on the threshold, `Unhandled` below it and
    // `BelowThreshold` at it, so the property is that it falls closed and says so.
    assert!(
        planned
            .notes()
            .iter()
            .any(|note| note.severity().diverges_from_database()),
        "falling closed on an undeclared key has to be disclosed, not silent"
    );
}

/// A table spelled as a well-known type is refused, not renamed.
///
/// Precondition 7, and the reason the grammar does not admit it: the caller type and the
/// role type are configurable, so a table arriving with one of those names cannot be
/// disambiguated without deciding which of the two the operator meant.
#[test]
fn a_table_named_as_a_reserved_type_is_refused() {
    for name in ["user", "pg_role"] {
        let schema = format!(
            "CREATE TABLE \"{name}\" (id TEXT PRIMARY KEY, who TEXT NOT NULL);
ALTER TABLE \"{name}\" ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON \"{name}\" FOR SELECT USING (who = current_setting('app.who', true));
"
        );
        let (classified, db, registry) =
            support::classify_sql_with_settings(&schema, [declared_key()]);
        let refusal = Translation::plan(
            classified,
            &db,
            &registry,
            ConfidenceLevel::B,
            &GeneratorSettings::default(),
        )
        .expect_err("a table named as a well-known type has to be refused");
        assert!(
            format!("{refusal:?}").contains("ReservedTypeName"),
            "the refusal has to name the collision, got {refusal:?}"
        );
    }
}

/// A folded collision reaches the translation as two types, not one.
///
/// The axis is worthless if the two tables arrive as one type or if one of them is dropped:
/// the parity that follows would then be about a single table and would pass whatever the
/// collision did.
#[test]
fn a_folded_collision_plans_two_distinct_types() {
    let collisions: Vec<_> = every_case()
        .into_iter()
        .filter(|case| case.name.contains("folded-collision"))
        .collect();
    assert!(!collisions.is_empty(), "no collision case to check");
    for case in collisions {
        let planned = plan(&case.schema);
        let types: Vec<String> = planned
            .row_naming()
            .iter()
            .map(|entry| entry.type_name.as_str().to_string())
            .collect();
        // The names themselves, not merely two of them: the first table keeps the
        // canonical name and the second carries the suffix, and a regression in either the
        // base or the suffix has to fail here.
        assert_eq!(
            types,
            vec!["guarded".to_string(), "guarded_9d480982".to_string()],
            "{}: the collision has to resolve to the canonical name and one suffixed",
            case.name
        );
    }
}

/// A long-key case really carries a long key.
///
/// The axis exists to push an object name towards its cap, so a seed that quietly went back
/// to short keys would measure nothing.
#[test]
fn a_long_key_case_seeds_a_key_near_the_cap() {
    let long: Vec<_> = every_case()
        .into_iter()
        .filter(|case| case.name.contains("long-key") && case.name.contains("text"))
        .collect();
    assert!(!long.is_empty(), "no long-key text case to check");
    for case in long {
        let width = if case.name.contains("folded-collision") {
            // The suffixed type name and its separator.
            MAX_OBJECT_NAME_CHARS - 17
        } else {
            // `guarded` and a separator.
            MAX_OBJECT_NAME_CHARS - 8
        };
        assert!(
            case.seed[0].contains(&"l".repeat(width - 1)),
            "{}: the seed's key is not at the boundary the cap leaves",
            case.name
        );
        assert!(
            !case.seed[0].contains(&"l".repeat(width)),
            "{}: the seed's key is past the boundary, so the row has no name",
            case.name
        );
    }
}

/// The membership shape leaves its membership table unguarded, and one row unnamed.
///
/// Precondition 8 is an `ALTER TABLE` that must stay absent: with row security on and no
/// policy the membership table shows nobody anything, every read falls closed, and the case
/// would measure the refusal path instead of the join. The unnamed guarded row is the other
/// half: a model keyed on the table rather than the row would grant it.
#[test]
fn a_membership_case_leaves_its_membership_table_open_and_one_row_unnamed() {
    let joins: Vec<_> = every_case()
        .into_iter()
        .filter(|case| case.name.contains("membership") && case.name.contains("text"))
        .collect();
    assert!(!joins.is_empty(), "no membership case to check");
    for case in joins {
        assert!(
            !case
                .schema
                .contains("ALTER TABLE members_0 ENABLE ROW LEVEL SECURITY"),
            "{}: the membership table carries security of its own",
            case.name
        );
        assert!(
            case.schema.contains("EXISTS ("),
            "{}: the policy does not read a membership row",
            case.name
        );
        // The last key is a guarded row no membership row mentions.
        assert_eq!(
            case.seed[0].matches("'unnamed'").count(),
            1,
            "{}: every guarded row is named by a membership row, so nothing is denied \
             for want of one",
            case.name
        );
    }
}

/// Every partition of a depth case is disclosed as directly readable, naming the root.
///
/// The guard that makes depth an axis rather than decoration: the rows sit in partitions,
/// a read naming one is filtered by nothing, and the note has to name the ancestor that
/// carries the policies rather than the nearest parent. At depth three the nearest parent
/// carries none, which is where walking one level stopped being enough.
#[test]
fn every_partition_of_a_depth_case_is_disclosed_against_its_root() {
    for case in every_case()
        .into_iter()
        .filter(|case| case.name.contains("depth-t"))
    {
        // From the case's name and its schema, not from the list the notes are compared
        // against: reading the expectation off that list would let the whole axis shrink
        // and still agree with itself.
        let levels = if case.name.contains("depth-three") {
            2
        } else {
            1
        };
        assert_eq!(
            case.not_read_directly.len(),
            levels,
            "{}: the depth its name claims is not the depth it declares",
            case.name
        );
        if levels == 2 {
            assert!(
                case.schema.contains("PARTITION OF guarded_eu"),
                "{}: nothing is a partition of a partition, so the nearest parent still                  carries the policies",
                case.name
            );
        }
        let planned = plan(&case.schema);
        let disclosed: Vec<_> = planned
            .notes()
            .iter()
            .filter_map(|note| match note {
                TranslationNote::PartitionReadDirectlyIsUnfiltered { table, root } => {
                    Some((table, root))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            disclosed.len(),
            levels,
            "{}: one note per partition, got {disclosed:#?}",
            case.name
        );
        for partition in &case.not_read_directly {
            assert!(
                disclosed.iter().any(|(table, root)| {
                    table.to_string() == format!("public.{partition}")
                        && root.to_string() == "public.guarded"
                }),
                "{}: nothing discloses '{partition}' against the root that carries the policies",
                case.name
            );
        }
    }
}

/// No seed carries a caller's own value except the caller the case is about.
///
/// The runner asks the model about `user:<subject>` while `PostgreSQL` compares the row
/// against the caller's *setting*. Those line up only for the caller whose subject and
/// setting are the same string, so a row carrying another caller's setting is granted by the
/// database and denied by the model, and the case would report a disagreement about its own
/// seed rather than about the translation.
#[test]
fn no_seed_carries_another_callers_value() {
    let stray: Vec<&str> = CALLERS
        .iter()
        .filter_map(|caller| caller.value)
        .filter(|value| *value != "alice")
        .collect();
    assert!(!stray.is_empty(), "no caller holds a value of its own");
    for case in every_case() {
        for value in &stray {
            assert!(
                !case.seed[0].contains(&format!("'{value}'")),
                "{}: the seed carries '{value}', which is a caller's own setting",
                case.name
            );
        }
    }
}

/// A composed case translates both of its arms.
///
/// A parity run cannot prove this: dropping an arm from the schema changes what
/// `PostgreSQL` grants and what the model grants alike, so the two still agree and the case
/// passes while measuring half of what it claims. The translation is where the second arm is
/// either present or absent, so that is where the axis is guarded.
#[test]
fn a_composed_case_translates_both_of_its_arms() {
    let composed: Vec<_> = every_case()
        .into_iter()
        .filter(|case| case.name.contains("two-policies") || case.name.contains("or-clause"))
        .collect();
    assert!(!composed.is_empty(), "no composed case to check");
    for case in composed {
        let sources = arm_sources(&case.schema);
        assert_eq!(
            sources, 2,
            "{}: the two arms have to reach the model as two sources, got {sources}",
            case.name
        );
    }
    // And the uncomposed shape carries one, so the count above is about composition rather
    // than about every table having two.
    let single = every_case()
        .into_iter()
        .find(|case| case.name.contains("one-clause") && case.name.contains("self"))
        .expect("a one-clause case");
    assert_eq!(arm_sources(&single.schema), 1);
}

/// How many ownership sources a schema's read is built from.
fn arm_sources(schema: &str) -> usize {
    plan(schema)
        .outputs_accepting_gaps()
        .tuple_queries()
        .iter()
        .filter(|query| query.comment.contains("ownership"))
        .count()
}

/// A forced case hands its owner no bypass, and an unforced one names them.
///
/// The parity run alone cannot prove the axis: `FORCE` matters only because a role the case
/// reads as owns the table, and dropping either half leaves a case that still agrees. So the
/// translation answers both halves here, with the table handed to the role the case acts as,
/// since only an acting role's exemption a note can name. With `FORCE` there is nothing to
/// report, and with it removed the report has to name that role.
#[test]
fn a_forced_case_hands_its_owner_no_bypass() {
    let owned: Vec<_> = every_case()
        .into_iter()
        .filter(|case| case.name.contains("forced-owner"))
        .collect();
    assert!(!owned.is_empty(), "no owned case to check");
    for case in owned {
        let as_acting_owner = |forced: bool| {
            let mut schema = case.schema.replace(
                "ALTER TABLE \"guarded\" OWNER TO alice;",
                "ALTER TABLE \"guarded\" OWNER TO app_user;",
            );
            if !forced {
                schema = schema.replace("ALTER TABLE \"guarded\" FORCE ROW LEVEL SECURITY;\n", "");
            }
            schema
        };
        let forced = owner_exemptions(&as_acting_owner(true));
        assert!(
            forced.is_empty(),
            "{}: FORCE leaves no owner exempt, got {forced:?}",
            case.name
        );
        let unforced = owner_exemptions(&as_acting_owner(false));
        assert!(
            unforced.iter().any(|note| note.contains("app_user")),
            "{}: unforced, the exempt owner is the role the case acts as, got {unforced:?}",
            case.name
        );
    }
}

/// What a schema reports about the acting roles its tables exempt.
fn owner_exemptions(schema: &str) -> Vec<String> {
    plan(schema)
        .outputs_accepting_gaps()
        .notes()
        .iter()
        .filter(|note| matches!(note, TranslationNote::ActingRoleExempt { .. }))
        .map(TranslationNote::message)
        .collect()
}

/// A write case declares every command, changes what no policy reads, and reads a column of
/// its own per command.
///
/// Three claims the runner takes on trust. It asks the model about the row that exists rather
/// than the row a write would produce, which holds only where neither the key nor the
/// changed column is read by a policy. A command whose policy is missing falls to
/// `no_access`, which the database mirrors, so the parity run would agree while comparing
/// nothing: the four answers have to be judged. And one predicate shared by every command
/// would agree whatever the commands were wired to, so a change and a removal each read a
/// column the read does not.
#[test]
fn a_write_case_judges_every_command_and_changes_what_no_policy_reads() {
    let writing: Vec<_> = every_case()
        .into_iter()
        .filter(|case| case.writes.is_some())
        .collect();
    assert!(!writing.is_empty(), "no write case to check");
    for case in writing {
        let set = &case.writes.as_ref().expect("filtered on it").update_set;
        let changed = set
            .split('=')
            .next()
            .expect("a SET clause names a column")
            .trim();
        let planned = plan(&case.schema);
        for policy in case.schema.lines().filter(|line| line.contains("POLICY")) {
            assert!(
                !policy.contains(changed) && !policy.contains("id"),
                "{}: a policy reads {changed} or the key, so a write is not settled by the \
                 existing row: {policy}",
                case.name
            );
        }
        for (command, column) in [("UPDATE", "editor"), ("DELETE", "remover")] {
            let policy = case
                .schema
                .lines()
                .find(|line| line.contains(&format!("FOR {command}")))
                .unwrap_or_else(|| panic!("{}: no {command} policy", case.name));
            assert!(
                policy.contains(column),
                "{}: {command} reads what the read reads, so a miswired command still \
                 agrees: {policy}",
                case.name
            );
            let read = case
                .schema
                .lines()
                .find(|line| line.contains("FOR SELECT"))
                .expect("a read policy");
            assert!(
                !read.contains(column),
                "{}: the read reads {column} too, so the commands are not told apart: {read}",
                case.name
            );
        }
        for statement in [
            ActionStatement::Select,
            ActionStatement::Insert,
            ActionStatement::Update,
            ActionStatement::Delete,
        ] {
            let answer = planned
                .action_relations()
                .iter()
                .find(|entry| entry.statement == statement)
                .map(|entry| &entry.answer);
            assert!(
                matches!(answer, Some(ActionAnswer::Judged(_))),
                "{}: {statement:?} is {answer:?}, so the case compares nothing for it",
                case.name
            );
        }
    }
}

/// A barrier reaches the model, and takes a seeded row away.
///
/// Removing the barrier from the schema changes what the database grants and what the model
/// grants alike, so the parity run cannot tell a translation that drops barriers from one
/// that honours them. The model is where the difference has to show: with the barrier and
/// without it, the two `OpenFGA` models cannot be the same text.
///
/// Reaching the model is not enough either. A barrier reading the column the permissive
/// clause reads narrows nothing, so it has to read another one, and the seed has to carry a
/// row the permissive clause grants and both barrier shapes remove.
#[test]
fn a_barrier_reaches_the_model() {
    let barred: Vec<_> = every_case()
        .into_iter()
        .filter(|case| case.name.contains("barrier-on"))
        .collect();
    assert!(!barred.is_empty(), "no barrier case to check");
    for case in barred {
        let without: String = case
            .schema
            .split_inclusive(";\n")
            .filter(|statement| !statement.contains("AS RESTRICTIVE"))
            .collect();
        assert_ne!(
            without, case.schema,
            "{}: no restrictive policy to remove",
            case.name
        );
        let permissive = case
            .schema
            .lines()
            .find(|line| line.contains("FOR SELECT USING"))
            .expect("a permissive clause");
        let narrowing = case
            .schema
            .lines()
            .find(|line| line.contains("USING (tenant") || line.contains("USING (archived"))
            .unwrap_or_else(|| panic!("{}: the barrier reads no column of its own", case.name));
        // The left of each equality, since the accessor spells the request key `app.who`
        // and the whole line would name the permissive column for that reason alone.
        let column_of = |clause: &str| {
            clause
                .split('=')
                .next()
                .expect("an equality has a left side")
                .to_string()
        };
        assert!(
            !column_of(narrowing).contains("who") && column_of(permissive).contains("who"),
            "{}: the barrier reads what the permissive clause reads, so it narrows \
             nothing: {narrowing}",
            case.name
        );
        assert!(
            case.seed[0].contains("'alice', 'someone_else', true"),
            "{}: no seeded row is granted by the clause and removed by either barrier",
            case.name
        );
        assert_ne!(
            plan(&case.schema).outputs_accepting_gaps().model(),
            plan(&without).outputs_accepting_gaps().model(),
            "{}: the barrier leaves the model unchanged, so it grants what it narrows",
            case.name
        );
    }
}
