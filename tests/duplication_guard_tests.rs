//! One rule, one spelling. Each guard states a property of the whole crate and names the
//! files exempt from it, rather than naming the files it searches.
//!
//! That direction matters. A guard listing the modules it reads goes quiet the moment a
//! file is added outside the list, and six modules had drifted outside every list,
//! `describe.rs` among them, which is how a second identifier escaper lived there
//! unnoticed. Searching everything and exempting deliberately fails towards noticing.

use std::fs;
use std::path::{Path, PathBuf};

/// Read a single module's source, test code included.
///
/// For the two guards that are about one file rather than about the crate.
fn read_module(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

/// The production half of one module's source, with every `#[cfg(test)] mod tests` block
/// removed and everything else kept.
///
/// A test spells a name on purpose and a helper it defines is not a second
/// implementation, so test code is cut. Only the block is cut, though: truncating at the
/// boundary instead would put any item written below the test module outside every guard
/// in this file, which is the same fail-open shape the guards exist to prevent. A
/// `#[cfg(test)]` item that is not `mod tests` is production-shaped and stays counted.
fn production_code(source: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let mut kept: Vec<&str> = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let opens_test_module = lines[index].trim() == "#[cfg(test)]"
            && lines
                .get(index + 1)
                .is_some_and(|next| next.trim().starts_with("mod tests"));
        if !opens_test_module {
            kept.push(lines[index]);
            index += 1;
            continue;
        }
        // A top-level module closes on a `}` in the first column, which no brace inside
        // it reaches under rustfmt, and `fmt --check` is a gate row.
        index = lines[index + 1..]
            .iter()
            .position(|line| *line == "}")
            .map_or(lines.len(), |offset| index + offset + 2);
    }
    kept.join("\n")
}

/// Every `.rs` file under `dir`, depth first and in a stable order.
fn walk(dir: &Path, into: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("failed to read dir {}: {e}", dir.display()))
        .map(|entry| entry.expect("dir entry").path())
        .collect();
    entries.sort();
    for entry in entries {
        if entry.is_dir() {
            walk(&entry, into);
        } else if entry.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            into.push(entry);
        }
    }
}

/// Every `.rs` file under `tests`, as `(path, source)`, verbatim.
///
/// The guards below read production code, because a test spells a name on purpose. This
/// reads the test tree for the one guard that is about the test harness itself.
fn test_modules() -> Vec<(String, String)> {
    let mut paths = Vec::new();
    walk(Path::new("tests"), &mut paths);
    paths
        .into_iter()
        .map(|path| {
            let source = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
            (path.display().to_string(), source)
        })
        .collect()
}

/// Every `.rs` file under `src` carrying production code, as `(path, source)`.
///
/// A whole `tests.rs` is skipped, and every other file is reduced to its production half
/// by [`production_code`].
fn src_modules() -> Vec<(String, String)> {
    let mut paths = Vec::new();
    walk(Path::new("src"), &mut paths);
    walk(Path::new("types/src"), &mut paths);

    paths
        .into_iter()
        .filter(|path| path.file_name().and_then(|name| name.to_str()) != Some("tests.rs"))
        .map(|path| {
            let source = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
            (path.display().to_string(), production_code(&source))
        })
        .collect()
}

/// Count `needle` across every production module.
fn count_all(needle: &str) -> usize {
    count_excluding(&[], needle)
}

/// Count `needle` across every production module except `exempt`.
///
/// An exempt path that names no module is a failure rather than a silent widening, so a
/// rename says so instead of surfacing as a confusing count.
fn count_excluding(exempt: &[&str], needle: &str) -> usize {
    let modules = src_modules();
    for path in exempt {
        assert!(
            modules.iter().any(|(name, _)| name == path),
            "exempt path `{path}` names no production module"
        );
    }
    modules
        .iter()
        .filter(|(path, _)| !exempt.contains(&path.as_str()))
        .map(|(_, source)| source.matches(needle).count())
        .sum()
}

/// Count definitions of `name`, whether or not it carries a generic parameter list.
fn fn_definitions(name: &str) -> usize {
    count_all(&format!("fn {name}(")) + count_all(&format!("fn {name}<"))
}

/// The function name a declaration line introduces.
fn declared_fn_name(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let head = ["pub(crate) ", "pub(super) ", "pub "]
        .iter()
        .find_map(|prefix| trimmed.strip_prefix(prefix))
        .unwrap_or(trimmed);
    let head = head.strip_prefix("const ").unwrap_or(head);
    let head = head.strip_prefix("async ").unwrap_or(head);
    let after = head.strip_prefix("fn ")?;
    let end = after.find(|ch: char| !ch.is_alphanumeric() && ch != '_')?;
    after.get(..end).filter(|name| !name.is_empty())
}

/// The item beginning at `start`, and the index of the line it closes on.
fn block_from(lines: &[&str], start: usize) -> (String, usize) {
    let mut depth = 0usize;
    let mut opened = false;
    let mut body = String::new();
    for (offset, line) in lines[start..].iter().enumerate() {
        body.push_str(line);
        body.push('\n');
        for ch in line.chars() {
            match ch {
                '{' => {
                    depth += 1;
                    opened = true;
                }
                '}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        if opened && depth == 0 {
            return (body, start + offset);
        }
    }
    (body, lines.len().saturating_sub(1))
}

/// Every function in `src` whose body `accept` admits, as `path:line: name`.
///
/// A guard counting a name proves the name is unique, never that the rule is. Two byte
/// identical peelers lived under different names while `fn unwrap_cast_or_nested(`
/// counted one, so a rule that must exist once has to be read off the body instead.
fn fns_whose_body(mut accept: impl FnMut(&str) -> bool) -> Vec<String> {
    let mut found = Vec::new();
    for (path, source) in src_modules() {
        let lines: Vec<&str> = source.lines().collect();
        let mut index = 0;
        while index < lines.len() {
            let Some(name) = lines.get(index).and_then(|line| declared_fn_name(line)) else {
                index += 1;
                continue;
            };
            let (body, end) = block_from(&lines, index);
            if accept(&body) {
                found.push(format!("{path}:{}: {name}", index + 1));
            }
            index = end.max(index) + 1;
        }
    }
    found
}

/// The walk itself, since every guard below is vacuous if it returns nothing.
///
/// The named files are the six that had drifted outside every guard's list. Pinning them
/// keeps the fix from being undone by a scoping mistake nobody notices.
#[test]
fn the_walk_reaches_every_source_file() {
    let modules = src_modules();

    assert!(
        modules.len() > 30,
        "the walk found only {} modules, so the guards below prove nothing",
        modules.len()
    );

    // Aggregate rather than per file. A new module has to cost nothing here, or the
    // inversion trades a guard that goes quiet for one that cries wolf, and an empty
    // file is the smallest new module there is.
    let total: usize = modules.iter().map(|(_, source)| source.len()).sum();
    assert!(
        total > 500_000,
        "the walk read only {total} bytes, so the guards below prove little"
    );

    for expected in [
        "src/lib.rs",
        "src/term.rs",
        "src/translator.rs",
        "src/output/report.rs",
        "src/generator/describe.rs",
        "src/generator/row_naming.rs",
        "src/generator/identity.rs",
        "src/generator/well_known.rs",
        "src/classifier/oracle.rs",
    ] {
        assert!(
            modules.iter().any(|(path, _)| path == expected),
            "{expected} is outside the walk, so no guard sees it"
        );
    }

    // The two test files are skipped, so a name a test spells is not a second spelling.
    assert!(
        !modules.iter().any(|(path, _)| path.ends_with("tests.rs")),
        "a whole test file reached the walk"
    );
}

/// Cutting the test module must not cut what follows it.
///
/// An item written below `mod tests` is production code, and truncating at the boundary
/// puts it outside every guard in this file, which is the fail-open shape these guards
/// exist to prevent. Found by a P3 mutation that went unnoticed for exactly that reason.
/// Written against a synthetic module rather than the tree, since no file has that shape
/// today and the guard has to already hold for the one that does.
#[test]
fn the_walk_keeps_production_code_that_follows_a_test_module() {
    let source = r#"fn before() {}

#[cfg(test)]
mod tests {
    #[test]
    fn helper_named_like_production() {
        let unbalanced = "{";
    }
}

fn after() {}
"#;
    let kept = production_code(source);
    assert!(kept.contains("fn before()"), "the head survives:\n{kept}");
    assert!(
        kept.contains("fn after()"),
        "an item below the test module is production code:\n{kept}"
    );
    assert!(
        !kept.contains("helper_named_like_production"),
        "the test module itself is still cut:\n{kept}"
    );

    // The doc claims this, so it is asserted rather than trusted: only `mod tests` is
    // cut, and a `#[cfg(test)]` item of any other kind is production-shaped.
    let inline = r#"#[cfg(test)]
const SAMPLE: &str = "x";

fn after() {}
"#;
    let kept = production_code(inline);
    assert!(
        kept.contains("SAMPLE") && kept.contains("fn after()"),
        "a cfg(test) item that is not a test module stays:\n{kept}"
    );
}

#[test]
fn confidence_filtering_has_single_source_of_truth() {
    let definitions = fn_definitions("filter_policies_for_output");

    assert_eq!(
        definitions, 1,
        "expected a single confidence filtering implementation, found {definitions}"
    );
}

#[test]
fn row_identity_resolution_has_single_source_of_truth() {
    let definitions = fn_definitions("resolve_row_identity");

    assert_eq!(
        definitions, 1,
        "expected a single row-identity implementation, found {definitions}"
    );

    // The single-column answer is derived from the list rather than resolved again.
    // A second resolution here is how a caller ends up naming a row one way while the
    // rest of the crate names it another.
    let single = fn_definitions("single_identity_column");

    assert_eq!(
        single, 1,
        "expected a single narrowing helper, found {single}"
    );
}

#[test]
fn function_arg_extraction_has_single_source_of_truth() {
    let expr_defs = fn_definitions("function_arg_expr");

    assert_eq!(
        expr_defs, 1,
        "expected a single function_arg_expr implementation, found {expr_defs}"
    );
}

/// Note prose lives in one module and is rendered from the typed cause, so a note
/// cannot say one thing while its kind says another, and no construction site can
/// grow a second wording for the same gap.
#[test]
fn translation_note_prose_lives_only_in_the_notes_module() {
    let centralized = count_all(
        "stable object IDs need a single-column primary key or a NOT NULL UNIQUE `id` column",
    );
    assert_eq!(
        centralized, 1,
        "expected the missing-object-id advice once, found {centralized}"
    );

    // Exempt: `notes.rs` is where the prose belongs.
    //
    // Two shapes, because one literal is what let a second wording through. The report
    // rendered `REVIEW: attribute condition on '...'` for the same gap `notes.rs` already
    // phrased twice, and this guard named the report's own file while looking only for the
    // comment marker. A guard aimed at a concept and spelled as one string is blind to a
    // synonym, so the report now renders notes rather than writing them, and both the
    // marker and the standing-out prefix are refused everywhere else.
    for wording in ["-- TODO [Level", "REVIEW:"] {
        let stray = count_excluding(&["src/generator/notes.rs"], wording);
        assert_eq!(
            stray, 0,
            "note prose belongs to notes.rs, found {stray} of '{wording}' elsewhere"
        );
    }
}

/// Every pattern the classifier can produce has a row in the README's table.
///
/// The README is the crate's rustdoc landing page through `include_str!`, so it is the only
/// place a consumer learns which shapes translate. Five patterns had been added without
/// rows, and the prose still claimed a count that was wrong for the rows it did have, so
/// the count is gone and the rows are checked instead. The variant names come from the enum
/// definition, which cannot drift from itself.
#[test]
fn every_pattern_has_a_readme_row() {
    let patterns = read_module("src/classifier/patterns.rs");
    let body = patterns
        .split_once("pub enum PatternClass {")
        .expect("PatternClass is declared")
        .1
        .split_once("\n}")
        .expect("the declaration closes")
        .0;

    // Each variant now carries a named payload, so it reads `P4ExistsMembership(Payload),`
    // rather than opening a brace.
    let variants: Vec<&str> = body
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("P"))
        .filter_map(|line| line.split_once('('))
        .map(|(name, _)| name)
        .collect();

    assert!(
        variants.len() > 15,
        "only {} variants parsed out of the enum, so this proves nothing: {variants:?}",
        variants.len()
    );

    let readme = read_module("README.md");
    for variant in variants {
        // `P4ExistsMembership` is documented as row `P4` naming `ExistsMembership`, which
        // is the split the table's first two columns already make.
        let (number, name) = variant.split_at(
            variant
                .find(|ch: char| ch.is_ascii_alphabetic())
                .expect("a variant carries a name after its number"),
        );
        let row = format!("| P{number} | `{name}` |");
        assert!(
            readme.contains(&row),
            "README has no row `{row}` for PatternClass::P{number}{name}"
        );
    }
}

/// Every pattern's fields are declared once, by its payload struct.
///
/// `PatternClass` used to declare nineteen inline record types, which is why extracting an
/// arm needed up to eleven arguments and why an argument struct would have restated the same
/// field names beside the enum. Tuple variants make that impossible: a field can only be
/// added to the payload, so the recognizer that builds it and the emitter that reads it
/// cannot disagree about what the pattern holds.
#[test]
fn a_pattern_declares_its_fields_in_one_place() {
    let patterns = read_module("src/classifier/patterns.rs");
    let body = patterns
        .split_once("pub enum PatternClass {")
        .expect("PatternClass is declared")
        .1
        .split_once("\n}")
        .expect("the declaration closes")
        .0;

    let inline: Vec<&str> = body
        .lines()
        .map(str::trim)
        .filter(|line| line.ends_with('{'))
        .collect();
    assert!(
        inline.is_empty(),
        "a variant declaring its fields inline puts them in two places once a handler takes \
         them as arguments, found {inline:?}"
    );
}

/// Taking a table's plan out of the map and putting it back is one bracket.
///
/// The plan has to leave the map while a table is built, because minting a parent or holder type
/// needs the map mutably at the same time and nothing can hold both. Writing into the map for the
/// table currently being built is therefore discarded by the put-back, which is on the trap list
/// twice. `with_table_plan` owns both halves, so a second `remove` or `insert` on that map is the
/// shape that reintroduces the defect.
#[test]
fn a_table_plan_leaves_and_re_enters_the_map_in_one_place() {
    let source = read_module("src/generator/model_generator/mod.rs");

    let brackets = source.matches("fn with_table_plan<").count();
    assert_eq!(
        brackets, 1,
        "one bracket owns the pairing, found {brackets}"
    );

    for call in ["all_types.remove(", "all_types.insert("] {
        let uses = source.matches(call).count();
        assert_eq!(
            uses, 1,
            "'{call}' belongs to with_table_plan alone, found {uses}"
        );
    }
}

#[test]
fn p5_inheritance_analysis_has_single_source_of_truth() {
    let definitions = fn_definitions("analyze_p5_parent_inheritance");
    assert_eq!(
        definitions, 1,
        "expected a single P5 inheritance analysis helper, found {definitions}"
    );
}

/// The name a `<thing>_id` column gives the entity it references is decided once.
///
/// Every caller reaches it through `parent_type_from_fk_column` rather than stripping the
/// suffix itself, so a change to the rule cannot move a parent type while leaving an
/// ownership relation on the old spelling.
#[test]
fn the_name_an_id_column_references_has_a_single_source_of_truth() {
    let definitions = fn_definitions("parent_type_from_fk_column");
    assert_eq!(
        definitions, 1,
        "expected one 'fn parent_type_from_fk_column', found {definitions}"
    );

    // Exempt: `names.rs` holds the rule itself.
    let stray = count_excluding(&["src/parser/names.rs"], r#"strip_suffix("_id")"#);
    assert_eq!(
        stray, 0,
        "the suffix rule is reached through parent_type_from_fk_column, \
         found {stray} hand-rolled strips"
    );
}

/// `FROM ONLY` keeps an inheritance parent's child rows out of its object-minting
/// queries, and which reads carry it is one rule: a second `ONLY` spelling site could
/// scope a foreign-table read, which denies rows `PostgreSQL` grants, or miss an
/// owner-table read, which merges child rows into parent objects.
#[test]
fn the_from_only_scope_has_a_single_source_of_truth() {
    let definitions = fn_definitions("owner_table_reference");
    assert_eq!(
        definitions, 1,
        "expected one 'fn owner_table_reference', found {definitions}"
    );

    let spellings = count_all("\"ONLY {");
    assert_eq!(
        spellings, 1,
        "the ONLY prefix must be rendered by owner_table_reference alone, \
         found {spellings} spellings"
    );
}

/// Three spellings reach P4 membership: `EXISTS`, `col IN (SELECT ...)`, and the caller on
/// the left. The last two are one rewrite into the first, so all three land on one
/// analyzer. A second analyzer, or a second reader of the projection, would let one
/// spelling keep a refusal another dropped.
#[test]
fn membership_analysis_has_a_single_source_of_truth() {
    for name in [
        "analyze_membership_select",
        "membership_subquery_operands",
        "membership_exists_from_in_subquery",
        // Every spelling reads its subquery through one of these two extractors, so the
        // refusals below cannot be dropped by one spelling and kept by another.
        "exists_subquery_select",
        "select_result_shaping_clause",
        "exists_emptying_limit_clause",
        "any_named_source",
        "query_binds_its_own_names",
        "query_locks_its_rows",
        "query_level_refusal",
    ] {
        let definitions = fn_definitions(name);
        assert_eq!(
            definitions, 1,
            "expected one 'fn {name}', found {definitions}"
        );
    }

    // Each clause by which a subquery stops being the plain set of rows in the table it
    // names is read in exactly one place. A second reader would let one spelling keep a
    // refusal another spelling dropped.
    for clause in [
        "limit_clause.is_some()",
        "fetch.is_some()",
        "having.is_some()",
        "qualify.is_some()",
        "Distinct::On",
        "sample: Some(_)",
        "TableInheritance::Only",
        "with.is_some()",
        "locks.is_empty()",
    ] {
        let readers = count_all(clause);
        assert_eq!(
            readers, 1,
            "'{clause}' decides a refusal in one place, found {readers}"
        );
    }

    // The projected column of an `IN` subquery is a correlation, not a hint. Reading it
    // anywhere but the rewrite is how it used to reach the pattern without facing the
    // conflict check, which dropped a second correlation and granted the table whole.
    //
    // Scoped to one file on purpose, unlike the guards above: reading a projection is an
    // ordinary thing to do, and this says the membership analyzer does it once, not that
    // the crate does.
    let membership = read_module("src/classifier/recognizers/subquery/mod.rs");
    let projection_readers = membership.matches("select.projection").count();
    assert_eq!(
        projection_readers, 1,
        "the projection is read only by the rewrite, found {projection_readers} readers"
    );
}

#[test]
fn bool_equality_extraction_has_single_source_of_truth() {
    let definitions = fn_definitions("extract_boolean_column_equality");
    assert_eq!(
        definitions, 1,
        "expected a single boolean equality extractor helper, found {definitions}"
    );
}

#[test]
fn role_in_list_extraction_has_single_source_of_truth() {
    let definitions = fn_definitions("extract_role_names_from_in_list");
    assert_eq!(
        definitions, 1,
        "expected one shared IN-list role extraction helper, found {definitions}"
    );
}

#[test]
fn token_pair_matching_has_single_source_of_truth() {
    let definitions = fn_definitions("has_token_pair");
    assert_eq!(
        definitions, 1,
        "expected one shared token-pair helper, found {definitions}"
    );
}

#[test]
fn relation_reference_walking_has_single_source_of_truth() {
    let walkers = count_all("visit_relations(");

    assert_eq!(
        walkers, 1,
        "walking an expression for the relations it reads belongs in one helper, found {walkers}"
    );
}

#[test]
fn action_relations_and_their_commands_are_paired_once() {
    let tables = count_all("fn action_relation_commands(");
    assert_eq!(
        tables, 1,
        "one table maps an action relation to its SQL command, found {tables}"
    );

    let strays = count_all("\"can_select\" => ");
    assert_eq!(
        strays, 0,
        "mapping a relation to a command by match duplicates that table, found {strays}"
    );

    let update_needs = count_all("ActionTarget::UpdateUsing, ActionTarget::UpdateCheck");
    assert_eq!(
        update_needs, 1,
        "one place says which clause targets a command needs, found {update_needs}"
    );
}

#[test]
fn reserved_relation_subjects_have_a_single_source_of_truth() {
    let definitions = fn_definitions("reserved_relation_subjects");
    assert_eq!(
        definitions, 1,
        "one place decides which relation names the generator keeps, found {definitions}"
    );
}

#[test]
fn generator_owned_relation_names_have_a_single_source_of_truth() {
    let definitions = fn_definitions("generator_defines");
    assert_eq!(
        definitions, 1,
        "one place decides which relation names a translated name may not take, found {definitions}"
    );
}

#[test]
fn well_known_names_have_a_single_source_of_truth() {
    // `well_known.rs` owns generator names. `patterns.rs` owns the membership
    // privilege's relation. `db_lookup.rs` names principal tables, and `names.rs`
    // matches words inside column names.
    let exempt = [
        "src/generator/well_known.rs",
        "src/generator/db_lookup.rs",
        "src/parser/names.rs",
        "types/src/patterns.rs",
    ];

    for name in [
        "user",
        "team",
        "pg_role",
        "no_access",
        "public_viewer",
        "member",
        "owner_user",
        "owner_team",
        "can_select",
        "can_insert",
        "can_update",
        "can_delete",
        "can_update_using",
        "can_update_check",
        "can_insert_returning",
        "can_upsert",
        "can_select_for_update",
    ] {
        let literals = count_excluding(&exempt, &format!("\"{name}\""));
        assert_eq!(
            literals, 0,
            "'{name}' has an extra source, found {literals} literals"
        );
    }
}

#[test]
fn blaming_an_unrecognized_clause_has_a_single_source_of_truth() {
    for needle in [
        "fn called_function_names(",
        "fn unrecognized_operators(",
        "fn describe_unrecognized_function(",
        // A constructor is told apart from a call in one place, and described in one
        // place. A second copy would let the two disagree about what can be registered.
        "fn takes_a_subquery(",
        "fn subquery_set_constructors(",
        "fn describe_set_constructor(",
        // One recognizer decides which array spellings name the caller, and one reads a
        // jsonb key chain. A second copy would let the classifier and the renderer
        // disagree about what the clause says.
        "fn array_membership_column(",
        "fn jsonb_text_path(",
        "fn quote_sql_string_literal(",
    ] {
        let definitions = count_all(needle);
        assert_eq!(
            definitions, 1,
            "expected one '{needle}', found {definitions}"
        );
    }

    // The operator reads these, so a second spelling would drift from the first.
    for fragment in [
        "not in registry and body not available",
        "did not match any recognized translation pattern",
        "is registered as Unknown",
        "is SQL syntax rather than a function call",
    ] {
        let uses = count_all(fragment);
        assert_eq!(
            uses, 1,
            "'{fragment}' must come from describe_unrecognized_function alone, found {uses}"
        );
    }

    // Array membership and jsonb ownership are exact only because one place expands the
    // array and one place renders the key chain. A second renderer would drift from the
    // semantics both were verified against.
    for needle in ["UNNEST(", "fn render_jsonb_path("] {
        let uses = count_all(needle);
        assert_eq!(uses, 1, "'{needle}' must have one source, found {uses}");
    }
}

/// One place turns an identifier into SQL text. A second escaper lets one site double an
/// interior quote while another does not, and `"a"b"` is not the column `a"b`: `PostgreSQL`
/// refuses to parse it, and a name chosen to close the quote rather than break it turns a
/// generated condition into a predicate of someone else's choosing.
#[test]
fn quoting_an_identifier_for_sql_has_a_single_source_of_truth() {
    for needle in ["fn quote_sql_identifier(", "fn bound_eq("] {
        let definitions = count_all(needle);
        assert_eq!(
            definitions, 1,
            "expected one '{needle}', found {definitions}"
        );
    }

    // Wrapping a name in quotes by hand is the bypass, since it skips the doubling.
    //
    // Exempt: `tuple_generator.rs` holds the escaper itself, and `quoted_for_lookup` in
    // `identifiers.rs` shares the doubling expression while deliberately not being SQL
    // text. It builds a key `lookup_table` resolves, leaving a bare lowercase name
    // unquoted, so it must not become SQL and must not be replaced by the escaper.
    let hand_quoted = count_excluding(
        &[
            "src/generator/tuple_generator.rs",
            "types/src/identifiers.rs",
        ],
        r#"\"{"#,
    );
    assert_eq!(
        hand_quoted, 0,
        "an identifier becomes SQL through quote_sql_identifier, found {hand_quoted} by hand"
    );

    let lookup_keys = fn_definitions("quoted_for_lookup");
    assert_eq!(
        lookup_keys, 1,
        "one lookup-key speller, found {lookup_keys}"
    );
}

/// One place turns a database value into the name of an object.
///
/// The row evaluator and the tuple SQL must agree about it byte for byte, or a replay
/// writes facts about an object nobody checks. The Rust and SQL renderings are compared by
/// the per-row parity suite; this is what stops a second Rust rendering existing for it to
/// disagree with.
#[test]
fn the_identity_encoder_has_a_single_source_of_truth() {
    for name in [
        "encode_part",
        "encode_identity",
        "hex_digit",
        "is_spelled_verbatim",
        "object_name_fits",
        "subject_name_fits",
    ] {
        let definitions = fn_definitions(name);
        assert_eq!(definitions, 1, "expected one `{name}`, found {definitions}");
    }

    for constant in [
        "SAFE_PUNCTUATION: &str",
        "ESCAPE_MARKER: char",
        "PART_SEPARATOR: char",
        "MAX_OBJECT_NAME_CHARS: usize",
        "MAX_SUBJECT_NAME_BYTES: usize",
        "WILDCARD_SUBJECT_ID: &str",
    ] {
        let declarations = count_all(constant);
        assert_eq!(
            declarations, 1,
            "expected one `{constant}`, found {declarations}"
        );
    }
}

/// One place decides what a schema name canonicalizes to, and it decides the whole
/// answer.
///
/// The reserved-word prefix used to be applied where a type was *defined*, after
/// collisions had been resolved against the unprefixed name, so two tables could collapse
/// onto one type and a cross-type reference could name a type the model never declared.
/// `TypeName::canonicalized` is idempotent on this function's output, which is what lets
/// the record templates re-wrap a name the generator already decided.
#[test]
fn a_type_name_is_decided_in_one_place() {
    let deciders = fn_definitions("canonical_fga_type_name");
    assert_eq!(
        deciders, 1,
        "expected one type-name canonicalizer, found {deciders}"
    );

    // The reserved-word and leading-digit prefix is `TypeName`'s rule. A second site
    // applying it is how the definition and the reference came to disagree.
    let prefixers = count_excluding(&["types/src/identifiers.rs"], "\"t_");
    assert_eq!(
        prefixers, 0,
        "the type-name prefix is TypeName's rule, found {prefixers} applying it elsewhere"
    );
}

/// A type name is stored as a `TypeName`, never as a bare string.
///
/// Relation names have carried `RelationName` since the types crate was split out, while
/// type names travelled as `String` beside them, so a table spelling could be handed to a
/// field expecting a type. That is how a reference came to name a type the model never
/// declared. Carrying the newtype also removes the re-wrapping in the record templates, so
/// the idempotence of the canonicalizer stops being load-bearing.
///
/// Stored fields only. A function that renders a name as text, or looks one up by its
/// rendered form, takes `&str` on purpose: `dsl::bare`, `TableTypes::spelling_of` and
/// `Recursion::blocked_targets`.
#[test]
fn a_type_name_is_stored_as_a_type_name() {
    // Named rather than matched by suffix: `return_type` and `data_type` are SQL types,
    // which are strings and stay strings.
    for field in [
        "type_name",
        "object_type",
        "subject_type",
        "owner_type",
        "parent_type",
        "guarded_type",
        "share_type",
        "holder_type",
        "scope_type",
        "user_type",
        "through_type",
    ] {
        let stringly = count_all(&format!("{field}: String,"));
        assert_eq!(
            stringly, 0,
            "a type name is stored as TypeName, found {stringly} declared `{field}: String`"
        );
    }

    // Exempt: `names.rs` holds the canonicalizer and `well_known.rs` names the five
    // generator types from literals. Everywhere else already holds a decided name.
    let rewraps = count_excluding(
        &["src/parser/names.rs", "src/generator/well_known.rs"],
        "TypeName::canonicalized(",
    );
    assert_eq!(
        rewraps, 0,
        "a decided type name is carried, not canonicalized again, found {rewraps} rewrapping"
    );
}

/// SQL text is read by the lexer the crate already depends on.
///
/// A hand-rolled scanner has to re-decide dollar quoting, nested comments, escaped quotes
/// and quoted identifiers, and it read an unterminated literal as empty rather than as a
/// body nobody can read. `sqlparser`'s tokenizer answers all of it and fails loudly.
#[test]
fn reading_sql_text_goes_through_the_lexer() {
    for name in [
        "sanitize_sql_for_keyword_scan",
        "scan_identifier_tokens",
        "parse_dollar_quote_delimiter",
        "is_dollar_tag_char",
        "is_dollar_tag_start_char",
        "next_non_whitespace_char",
    ] {
        let definitions = fn_definitions(name);
        assert_eq!(
            definitions, 0,
            "`{name}` re-decides what the lexer already decides, found {definitions}"
        );
    }

    // Exempt: `function_analyzer.rs` is the one module that lexes a body.
    let lexers = count_excluding(&["src/parser/function_analyzer.rs"], "Tokenizer::new(");
    assert_eq!(
        lexers, 0,
        "one module lexes a function body, found {lexers} more"
    );
}

/// One place decides that a parenthesis carries no meaning, and one place splits a
/// conjunction. A second peel would let one analyzer see through `pg_dump`'s
/// parentheses while another still refuses them.
///
/// These are the names. The rule they stand for is asserted next door, over bodies.
#[test]
fn parenthesis_peeling_has_a_single_source_of_truth() {
    for needle in [
        "fn unparenthesize(",
        "fn unwrap_cast_or_nested(",
        "fn flatten_and_predicates<",
    ] {
        let definitions = count_all(needle);
        assert_eq!(
            definitions, 1,
            "expected one '{needle}', found {definitions}"
        );
    }

    // The shape, rather than these names, is asserted by
    // `every_cast_peel_routes_through_the_shared_peeler`, which sees a peel re-spelled as
    // recursion as well as one re-spelled as a loop.

    // An extra membership predicate joins a conjunction of NULL guards, so every place
    // that splices one has to parenthesise it: a disjunction would otherwise break out
    // of the AND. Counting sites would break the moment a second one is added
    // correctly, so this asserts the property instead.
    let wrapped = count_all("AND ({e})");
    let bare = count_all("AND {e}");
    assert!(
        wrapped > 0,
        "the extra membership predicate must be spliced somewhere"
    );
    assert_eq!(
        bare, 0,
        "every splice of an extra predicate must parenthesise it, found {bare} that do not"
    );
}

/// Every plain cast peel goes through the shared peeler.
///
/// Two readers inspect the cast type before recursing or in place of it.
#[test]
fn every_cast_peel_routes_through_the_shared_peeler() {
    let own_peels = fns_whose_body(|body| {
        let after_signature = body.split_once('\n').map_or("", |(_, rest)| rest);
        body.contains("Expr::Cast")
            && !after_signature.contains("unwrap_cast_or_nested(")
            && !after_signature.contains("CastChain::peeled(")
    });
    let readers = [
        "peel_noting_casts",
        "conjunct_reads_only_the_row",
        "literal_uses_session_against_zoned_column",
    ];
    let unexpected: Vec<&String> = own_peels
        .iter()
        .filter(|found| {
            !readers
                .iter()
                .any(|reader| found.ends_with(&format!(": {reader}")))
        })
        .collect();

    for expected in readers {
        assert!(
            own_peels
                .iter()
                .any(|found| found.ends_with(&format!(": {expected}"))),
            "expected one cast reader named '{expected}'"
        );
    }
    assert!(
        unexpected.is_empty(),
        "a cast is peeled outside the three readers: {unexpected:#?}"
    );
}

/// One function turns a peeled expression into the string literal it spells.
///
/// `Value::SingleQuotedString(` is read in ten legitimate places, each accepting a
/// different neighbouring literal kind, so counting it says nothing. The rule that must
/// exist once is narrower: peel the casts and parentheses, then accept a single quoted
/// string and nothing else. `json_literal_key` and `string_literal` were that rule
/// spelled twice, in sibling modules, and no guard could see it.
#[test]
fn reading_a_string_literal_has_a_single_source_of_truth() {
    // Exactly one `Value::` arm is what separates this rule from `attribute_literal`,
    // which reads a string, a number or a boolean into one enum and is a different job.
    let readers = fns_whose_body(|body| {
        body.contains("unwrap_cast_or_nested(")
            && body.contains("Value::SingleQuotedString(")
            && body.matches("Value::").count() == 1
    });
    assert_eq!(
        readers.len(),
        1,
        "one peel-then-read-a-literal function, found {}: {readers:?}",
        readers.len()
    );
}

#[test]
fn sql_type_families_have_one_source_of_truth() {
    let local_kind_tables =
        fns_whose_body(|body| body.contains("ColumnKind::Text") && body.contains("\"TEXT\""));
    assert!(
        local_kind_tables.is_empty(),
        "column kinds must map from sql-traits, found {local_kind_tables:?}"
    );

    let string_classifiers = fns_whose_body(|body| {
        body.contains("to_lowercase()")
            && (body.contains(".data_type(") || body.contains("declared_column_type("))
    });
    assert!(
        string_classifiers.is_empty(),
        "column type families must come from sql-traits, found {string_classifiers:?}"
    );
}

#[test]
fn the_row_evaluator_holds_no_database_handle() {
    let source = [
        read_module("types/src/records.rs"),
        read_module("types/src/identity.rs"),
    ]
    .join("\n");

    for forbidden in [
        "ParserDB",
        "DatabaseLike",
        "diesel",
        "PgConnection",
        "Connection",
        "sql_query",
        "execute",
    ] {
        assert!(
            !source.contains(forbidden),
            "the row evaluator must not name `{forbidden}`"
        );
    }
}

#[test]
fn the_lightweight_contract_has_only_contract_dependencies() {
    let manifest = read_module("types/Cargo.toml");
    let dependencies = manifest
        .split_once("[dependencies]")
        .expect("the contract crate has dependencies")
        .1
        .split("\n[")
        .next()
        .expect("the dependency section ends");
    let mut names: Vec<&str> = dependencies
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('=').map(|(name, _)| name.trim()))
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["serde", "thiserror"]);
}

/// The first fenced block of `language` in `text`, without the fence lines.
fn fenced_block(text: &str, language: &str) -> String {
    let open = format!("```{language}\n");
    let start = text
        .find(&open)
        .unwrap_or_else(|| panic!("the README has no ```{language} fence"))
        + open.len();
    let end = text[start..]
        .find("\n```")
        .unwrap_or_else(|| panic!("the ```{language} fence never closes"))
        + start;
    text[start..end].to_string()
}

/// The README's example blocks are the crate's rustdoc landing page, and both had
/// drifted from the real output once. The schema, the model and the tuple SQL are
/// pinned together: the schema must appear in the usage fence, and the fga and sql
/// fences must hold exactly what that schema yields.
#[test]
fn the_readme_example_blocks_match_the_output() {
    let schema = "
    CREATE TABLE documents (
        id       UUID PRIMARY KEY,
        owner_id UUID NOT NULL
    );
    CREATE FUNCTION current_user_id() RETURNS UUID
        LANGUAGE sql STABLE
        AS 'SELECT current_setting(''app.current_user_id'', true)::uuid';
    ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
    CREATE POLICY documents_owner ON documents
        FOR SELECT TO PUBLIC
        USING (owner_id = current_user_id());
";
    let readme = read_module("README.md");
    assert!(
        readme.contains(schema),
        "the README usage fence no longer holds the schema this guard runs"
    );

    let db = rls2fga::parser::sql_parser::parse_schema(schema).expect("the schema parses");
    let caller = rls2fga::classifier::function_registry::SessionAttribute::setting(
        "app.current_user_id",
        rls2fga::classifier::function_registry::SessionAttributeKind::CallerId,
    )
    .with_identity_cast("uuid");
    assert!(
        readme.contains(".with_identity_cast(\"uuid\")"),
        "the README usage fence no longer declares the caller this guard declares"
    );
    let outputs = rls2fga::translator::TranslatorBuilder::new()
        .with_min_confidence(rls2fga::types::ConfidenceLevel::B)
        .with_session_attributes([caller])
        .build()
        .translate(&db)
        .expect("the schema plans")
        .outputs()
        .expect("every clause translates");

    assert_eq!(
        outputs.model().trim_end(),
        fenced_block(&readme, "fga").trim_end(),
        "the README model block drifted from the output"
    );
    let rendered = rls2fga::generator::tuple_generator::format_tuples(outputs.tuple_queries());
    assert_eq!(
        rendered.trim_end(),
        fenced_block(&readme, "sql").trim_end(),
        "the README tuple block drifted from the output"
    );
}

/// `normalized_function_name` extracts the terminal identifier via `last_str`, not by rendering the full `ObjectName` to a string.
#[test]
fn terminal_function_name_does_not_render_object_name_to_string() {
    let offenders = fns_whose_body(|body| {
        body.contains("fn normalized_function_name(") && body.contains(".name.to_string()")
    });
    assert_eq!(
        offenders.len(),
        0,
        "normalized_function_name serializes ObjectName before extracting the terminal \
         identifier, route through sql_traits::utils::last_str instead: {offenders:?}"
    );
}

/// A raw argument-name arity walk must be paired with the stored-name walk used for substitution.
#[test]
fn function_argument_names_route_through_stored_argument_names() {
    let offenders = fns_whose_body(|body| {
        body.matches(".argument_names(").count() > body.matches(".stored_argument_names(").count()
    });
    assert_eq!(
        offenders.len(),
        0,
        "found unpaired direct argument_names call(s): {offenders:?}"
    );
}

/// No production module decides SQL identifier identity by folding quoting away.
///
/// `PostgreSQL` folds an unquoted identifier and keeps a quoted one, so a comparison that
/// strips quotes before deciding reads two different objects as one. Deleting the helpers
/// is what stops the mistake being respelled under another name.
#[test]
fn no_identifier_comparison_folds_quoting() {
    assert_eq!(
        fn_definitions("same_identifier"),
        0,
        "same_identifier compares two SQL identifiers quote-blind, route through \
         sql_traits::utils::identifier_resolution::identifiers_match instead"
    );
    assert_eq!(
        count_all("same_identifier("),
        0,
        "a caller still folds quoting away to compare identifiers"
    );
    assert_eq!(
        fn_definitions("normalize_identifier"),
        0,
        "normalize_identifier folds an identifier without knowing whether it was quoted"
    );
}

/// One startup policy for every container the suites run.
///
/// A hand-built image is a second copy of that policy, and the copies are what let the
/// retry cover 47 cases and miss the 48th.
#[test]
fn no_test_builds_a_container_image_outside_the_shared_helper() {
    let helper = "tests/support/containers.rs";
    let modules = test_modules();
    assert!(
        modules.iter().any(|(path, _)| path == helper),
        "the startup helper `{helper}` is gone, so this guard proves nothing"
    );

    let offenders: Vec<String> = modules
        .iter()
        .filter(|(path, _)| path != helper)
        .filter_map(|(path, source)| {
            // Split so this file does not count itself. Exempting it instead would be the
            // fail-open shape the header warns about.
            let count = source.matches(concat!("GenericImage", "::new(")).count();
            (count > 0).then(|| format!("{path}: {count}"))
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "these tests build a container image by hand, so the shared startup retry does not \
         cover them: {}",
        offenders.join(", ")
    );
}
