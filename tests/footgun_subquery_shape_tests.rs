//! Regression tests for inputs where the generated model or tuple SQL diverged
//! from `PostgreSQL` RLS semantics.
//!
//! Clauses by which a membership subquery stops being the plain set of rows in its table.

use rls2fga::classifier::patterns::{PatternClass, UnclassifiedExpr};
use rls2fga::types::ConfidenceLevel;

mod support;

use support::footgun::{
    db_of, is_structural_type, membership_translation, relation_definition,
    shaped_membership_subquery_complaints, translator, tuples_reading_from, type_names,
    TEAMS_SCHEMA,
};

/// `IN (SELECT ... LIMIT 1)` tests membership of one arbitrary row, not of the whole
/// result, so translating it as full membership grants rows the policy refuses. The
/// operand extractor is shared with the object-key spelling, which had the same hole.
#[test]
fn a_row_limited_membership_subquery_is_refused() {
    for clause in [
        "id = ANY (SELECT doc_id FROM doc_members WHERE user_id = current_user LIMIT 1)",
        "current_user IN (SELECT user_id FROM doc_members WHERE doc_id = docs.id LIMIT 1)",
        "id IN (SELECT doc_id FROM doc_members WHERE user_id = current_user FETCH FIRST 1 ROWS ONLY)",
    ] {
        let (dsl, _) = membership_translation(clause);
        assert_eq!(
            relation_definition(&dsl, "docs", "can_select").as_deref(),
            Some("no_access"),
            "`{clause}` limits the rows it tests, so it cannot be full membership:\n{dsl}"
        );
    }
}

/// Every spelling of a shaped subquery has to be refused, since they share one analyzer.
fn assert_every_spelling_refused(spellings: &[(&str, &str)]) {
    let complaints: Vec<String> = spellings
        .iter()
        .flat_map(|(clause, shaping)| shaped_membership_subquery_complaints(clause, shaping))
        .collect();
    assert!(
        complaints.is_empty(),
        "a subquery that shapes its rows must be refused in every spelling:\n{}",
        complaints.join("\n")
    );
}

/// `GROUP BY` collapses the rows into groups, so the subquery stops returning the rows a
/// membership relation would hold.
#[test]
fn a_grouped_membership_subquery_is_refused() {
    assert_every_spelling_refused(&[
        (
            "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
             AND user_id = current_user GROUP BY doc_id)",
            "GROUP BY",
        ),
        (
            "id IN (SELECT doc_id FROM doc_members WHERE user_id = current_user GROUP BY doc_id)",
            "GROUP BY",
        ),
        (
            "id = ANY (SELECT doc_id FROM doc_members WHERE user_id = current_user \
             GROUP BY doc_id)",
            "GROUP BY",
        ),
        (
            "current_user IN (SELECT user_id FROM doc_members WHERE doc_id = docs.id \
             GROUP BY user_id)",
            "GROUP BY",
        ),
    ]);
}

/// `HAVING count(*) > 1` is the two-person rule, admitting only rows backed by a second
/// membership row, while a membership relation grants every member.
#[test]
fn a_membership_subquery_filtered_by_having_is_refused() {
    assert_every_spelling_refused(&[
        (
            "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
             AND user_id = current_user HAVING count(*) > 1)",
            "HAVING",
        ),
        (
            "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
             AND user_id = current_user GROUP BY doc_id HAVING count(*) > 1)",
            "HAVING",
        ),
        (
            "id IN (SELECT doc_id FROM doc_members WHERE user_id = current_user \
             GROUP BY doc_id HAVING count(*) > 1)",
            "HAVING",
        ),
        (
            "id = ANY (SELECT doc_id FROM doc_members WHERE user_id = current_user \
             GROUP BY doc_id HAVING count(*) > 1)",
            "HAVING",
        ),
        (
            "current_user IN (SELECT user_id FROM doc_members WHERE doc_id = docs.id \
             GROUP BY user_id HAVING count(*) > 1)",
            "HAVING",
        ),
    ]);
}

/// `QUALIFY` filters on a window function, keeping one row per partition.
#[test]
fn a_qualify_filtered_membership_subquery_is_refused() {
    assert_every_spelling_refused(&[
        (
            "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id AND user_id = current_user \
             QUALIFY row_number() OVER (PARTITION BY doc_id ORDER BY role) = 1)",
            "QUALIFY",
        ),
        (
            "id IN (SELECT doc_id FROM doc_members WHERE user_id = current_user \
             QUALIFY row_number() OVER (PARTITION BY doc_id ORDER BY role) = 1)",
            "QUALIFY",
        ),
        (
            "id = ANY (SELECT doc_id FROM doc_members WHERE user_id = current_user \
             QUALIFY row_number() OVER (PARTITION BY doc_id ORDER BY role) = 1)",
            "QUALIFY",
        ),
        (
            "current_user IN (SELECT user_id FROM doc_members WHERE doc_id = docs.id \
             QUALIFY row_number() OVER (PARTITION BY user_id ORDER BY role) = 1)",
            "QUALIFY",
        ),
    ]);
}

/// `DISTINCT ON` keeps one arbitrary row per key and drops the rest.
#[test]
fn a_distinct_on_membership_subquery_is_refused() {
    assert_every_spelling_refused(&[
        (
            "EXISTS (SELECT DISTINCT ON (role) doc_id FROM doc_members \
             WHERE doc_id = docs.id AND user_id = current_user)",
            "DISTINCT ON",
        ),
        (
            "id IN (SELECT DISTINCT ON (role) doc_id FROM doc_members \
             WHERE user_id = current_user)",
            "DISTINCT ON",
        ),
        (
            "id = ANY (SELECT DISTINCT ON (role) doc_id FROM doc_members \
             WHERE user_id = current_user)",
            "DISTINCT ON",
        ),
        (
            "current_user IN (SELECT DISTINCT ON (role) user_id FROM doc_members \
             WHERE doc_id = docs.id)",
            "DISTINCT ON",
        ),
    ]);
}

/// `TABLESAMPLE` returns a fraction of the rows, so the subquery finds a fraction of the
/// memberships and a different fraction on every statement unless `REPEATABLE` pins it.
#[test]
fn a_sampled_membership_subquery_is_refused() {
    assert_every_spelling_refused(&[
        (
            "EXISTS (SELECT 1 FROM doc_members TABLESAMPLE BERNOULLI (10) \
             WHERE doc_id = docs.id AND user_id = current_user)",
            "TABLESAMPLE",
        ),
        (
            "id IN (SELECT doc_id FROM doc_members TABLESAMPLE BERNOULLI (10) \
             WHERE user_id = current_user)",
            "TABLESAMPLE",
        ),
        (
            "id = ANY (SELECT doc_id FROM doc_members TABLESAMPLE SYSTEM (10) \
             WHERE user_id = current_user)",
            "TABLESAMPLE",
        ),
        (
            "current_user IN (SELECT user_id FROM doc_members TABLESAMPLE SYSTEM (10) \
             REPEATABLE (42) WHERE doc_id = docs.id)",
            "TABLESAMPLE",
        ),
    ]);
}

/// `ONLY doc_members` reads the rows stored in `doc_members` itself and leaves out those of
/// every table inheriting from it, while the membership tuples are read from all of them.
#[test]
fn a_membership_subquery_reading_only_the_named_table_is_refused() {
    assert_every_spelling_refused(&[
        (
            "EXISTS (SELECT 1 FROM ONLY doc_members \
             WHERE doc_id = docs.id AND user_id = current_user)",
            "ONLY",
        ),
        (
            "id IN (SELECT doc_id FROM ONLY doc_members WHERE user_id = current_user)",
            "ONLY",
        ),
        (
            "id = ANY (SELECT doc_id FROM ONLY (doc_members) WHERE user_id = current_user)",
            "ONLY",
        ),
        (
            "current_user IN (SELECT user_id FROM ONLY doc_members WHERE doc_id = docs.id)",
            "ONLY",
        ),
    ]);
}

/// `doc_members *` spells out what `PostgreSQL` reads by default, the table and every
/// table inheriting from it, which is the relation the membership tuples read.
#[test]
fn a_membership_subquery_naming_the_inheriting_tables_translates_as_the_plain_table() {
    let plain =
        "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id AND user_id = current_user)";
    let (plain_dsl, plain_tuples) = membership_translation(plain);
    assert_ne!(
        relation_definition(&plain_dsl, "docs", "can_select").as_deref(),
        Some("no_access"),
        "the plain spelling must translate:\n{plain_dsl}"
    );
    assert_eq!(
        membership_translation(&plain.replace("doc_members", "doc_members *")),
        (plain_dsl, plain_tuples)
    );
}

/// Sampling a joined source can drop a parent row despite its declared foreign key.
#[test]
fn a_sampled_p5_join_partner_is_refused() {
    let db = db_of(
        r"
CREATE TABLE orgs(id UUID PRIMARY KEY);
CREATE TABLE parents(
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES orgs(id),
    owner_id TEXT NOT NULL
);
CREATE TABLE docs(id UUID PRIMARY KEY, parent_id UUID NOT NULL REFERENCES parents(id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (
    EXISTS (
        SELECT 1
        FROM parents AS p
        JOIN orgs AS o TABLESAMPLE BERNOULLI (10) ON o.id = p.org_id
        WHERE p.id = docs.parent_id AND p.owner_id = current_user
    )
);
",
    );
    let translator = translator(ConfidenceLevel::B);
    let classified = translator.classify(&db);
    let [policy] = classified.as_slice() else {
        panic!("expected one policy");
    };
    let PatternClass::Unknown(UnclassifiedExpr { reason, .. }) = &policy
        .using_classification()
        .expect("USING should classify")
        .pattern
    else {
        panic!(
            "TABLESAMPLE must refuse: {:#?}",
            policy.using_classification()
        );
    };
    assert!(
        reason.contains("TABLESAMPLE"),
        "the refusal must name TABLESAMPLE: {reason}"
    );
    let outputs = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    assert_eq!(
        relation_definition(&outputs.model(), "docs", "can_select").as_deref(),
        Some("no_access"),
        "a sampled join partner can remove a parent row:\n{}",
        outputs.model()
    );
}

/// A `WITH` clause binds a name inside the subquery, and that binding shadows the real
/// table of the same name, so the `FROM` no longer names the table the analyzer resolves.
///
/// Probed on `PostgreSQL` 18.4: the `EXISTS` spelling below admits 0 of 5 rows where the
/// same policy without the `WITH` admits all 5.
#[test]
fn a_membership_subquery_that_binds_its_own_names_is_refused() {
    assert_every_spelling_refused(&[
        (
            "EXISTS (WITH doc_members AS (SELECT doc_id, user_id FROM doc_members \
             WHERE role = 'nobody') SELECT 1 FROM doc_members \
             WHERE doc_id = docs.id AND user_id = current_user)",
            "WITH",
        ),
        (
            "id IN (WITH doc_members AS (SELECT doc_id, user_id FROM doc_members \
             WHERE role = 'nobody') SELECT doc_id FROM doc_members \
             WHERE user_id = current_user)",
            "WITH",
        ),
        (
            "id = ANY (WITH doc_members AS (SELECT doc_id, user_id FROM doc_members \
             WHERE role = 'nobody') SELECT doc_id FROM doc_members \
             WHERE user_id = current_user)",
            "WITH",
        ),
        (
            "current_user IN (WITH doc_members AS (SELECT doc_id, user_id FROM doc_members \
             WHERE role = 'nobody') SELECT user_id FROM doc_members \
             WHERE doc_id = docs.id)",
            "WITH",
        ),
    ]);
}

/// A locking read applies the locked table's `UPDATE` policies on top of its `SELECT`
/// ones, so the subquery finds fewer membership rows than the table holds.
///
/// Probed on `PostgreSQL` 18.4 with a membership table whose `UPDATE` policy admits three
/// of its ten rows: both `FOR UPDATE` and `FOR SHARE` admit 3 of 10 where the unlocked
/// spelling admits all 10. `FOR NO KEY UPDATE` and `FOR KEY SHARE` are absent here only
/// because `sqlparser` refuses them, see `docs/upstream/sqlparser-row-locking-clauses.md`.
#[test]
fn a_membership_subquery_that_locks_its_rows_is_refused() {
    assert_every_spelling_refused(&[
        (
            "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
             AND user_id = current_user FOR UPDATE)",
            "row lock",
        ),
        (
            "id IN (SELECT doc_id FROM doc_members WHERE user_id = current_user FOR UPDATE)",
            "row lock",
        ),
        (
            "id = ANY (SELECT doc_id FROM doc_members WHERE user_id = current_user FOR SHARE)",
            "row lock",
        ),
        (
            "current_user IN (SELECT user_id FROM doc_members WHERE doc_id = docs.id FOR SHARE)",
            "row lock",
        ),
    ]);
}

/// `EXISTS` is blind to a row limit that cannot empty the result, but `OFFSET` and a zero
/// limit can empty it, and then the policy admits fewer rows than full membership.
#[test]
fn an_exists_membership_subquery_whose_row_limit_can_empty_it_is_refused() {
    assert_every_spelling_refused(&[
        (
            "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
             AND user_id = current_user OFFSET 1)",
            "OFFSET",
        ),
        (
            "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
             AND user_id = current_user LIMIT 0)",
            "LIMIT",
        ),
        (
            "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
             AND user_id = current_user LIMIT (SELECT count(*) FROM doc_members))",
            "LIMIT",
        ),
        (
            "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
             AND user_id = current_user FETCH FIRST 0 ROWS ONLY)",
            "FETCH",
        ),
    ]);
}

/// The guard must not over-fire on plain `DISTINCT` either: dropping duplicate rows leaves
/// the set of values the membership test reads untouched.
#[test]
fn a_distinct_membership_subquery_still_translates() {
    let (expected_dsl, expected_tuples) = membership_translation(
        "id IN (SELECT doc_id FROM doc_members WHERE user_id = current_user)",
    );

    for clause in [
        "id IN (SELECT DISTINCT doc_id FROM doc_members WHERE user_id = current_user)",
        "id = ANY (SELECT DISTINCT doc_id FROM doc_members WHERE user_id = current_user)",
    ] {
        let (dsl, tuples) = membership_translation(clause);
        assert_eq!(
            dsl, expected_dsl,
            "`{clause}` tests the same set as the spelling without DISTINCT"
        );
        assert_eq!(
            tuples, expected_tuples,
            "`{clause}` must yield the same tuples as the spelling without DISTINCT"
        );
    }
}

/// Whatever is wrong with the refusal of a `SELECT` policy on `teams`, across the
/// classification, its reason, the model and the membership tuples alike. Empty when
/// every output refuses it and says why.
fn refused_teams_policy_complaints(clause: &str, reason_names: &str) -> Vec<String> {
    let db = db_of(&format!(
        "{TEAMS_SCHEMA}CREATE POLICY teams_members ON teams FOR SELECT USING ({clause});"
    ));
    let translator = translator(ConfidenceLevel::B);
    let mut complaints = Vec::new();

    let classified = translator.classify(&db);
    let [policy] = classified.as_slice() else {
        panic!("expected one classified policy for `{clause}`");
    };
    let pattern = &policy
        .using_classification()
        .expect("USING should classify")
        .pattern;
    match pattern {
        PatternClass::Unknown(UnclassifiedExpr { reason, .. }) if reason.contains(reason_names) => {
        }
        PatternClass::Unknown(UnclassifiedExpr { reason, .. }) => complaints.push(format!(
            "`{clause}` refuses without naming {reason_names}: {reason}"
        )),
        classified => complaints.push(format!("`{clause}` must not classify, got {classified:?}")),
    }

    let outputs = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    let can_select = relation_definition(&dsl, "teams", "can_select");
    if can_select.as_deref() != Some("no_access") {
        complaints.push(format!(
            "`{clause}` must fall closed, can_select is {can_select:?}"
        ));
    }
    let membership_tuples = tuples_reading_from(outputs.tuple_queries(), "\"members\"");
    if !membership_tuples.is_empty() {
        complaints.push(format!(
            "`{clause}` must emit no membership tuples, got {membership_tuples:?}"
        ));
    }
    // A type named after the projected column is the shape the phantom holder takes.
    let phantom: Vec<String> = type_names(&dsl)
        .into_iter()
        .filter(|name| name != "teams" && name != "members" && !is_structural_type(name))
        .collect();
    if !phantom.is_empty() {
        complaints.push(format!("`{clause}` invented the types {phantom:?}"));
    }
    complaints
}

/// A subquery selecting anything but a column has no column to correlate on, and taking
/// the outer one instead grants every membership row under a type named after it.
/// `min(team_id)` admits the lowest team alone on `PostgreSQL` 18, the model admitted
/// every team the caller belongs to.
#[test]
fn an_in_subquery_selecting_something_other_than_a_column_is_refused() {
    let complaints: Vec<String> = [
        "id IN (SELECT min(team_id) FROM members WHERE user_id = current_user)",
        "id = ANY (SELECT min(team_id) FROM members WHERE user_id = current_user)",
        "id IN (SELECT team_id || '' FROM members WHERE user_id = current_user)",
        "id IN (SELECT * FROM members WHERE user_id = current_user)",
        "id IN (SELECT row_number() OVER (ORDER BY team_id) FROM members \
         WHERE user_id = current_user)",
    ]
    .iter()
    .flat_map(|clause| {
        refused_teams_policy_complaints(clause, "selects an expression rather than a column")
    })
    .collect();
    assert!(
        complaints.is_empty(),
        "a subquery selecting no column cannot be membership:\n{}",
        complaints.join("\n")
    );
}

/// A cast changes the value, not only its type: `PostgreSQL` stores `(om.org_id)::uuid`
/// and matches the normalized uuid, while a tuple keyed on the raw column carries the
/// spelling the column holds. Probed on 18: the row is admitted by the policy and missed
/// by the tuple, so the cast cannot be dropped.
#[test]
fn an_in_subquery_selecting_a_cast_is_refused() {
    // Refused by the analyzer rather than by the projection guard: a cast is a column
    // reference, and what it cannot be is the key a tuple carries.
    let complaints = refused_teams_policy_complaints(
        "id IN (SELECT team_id::uuid FROM members WHERE user_id = current_user)",
        "could not infer a unique membership join",
    );
    assert!(
        complaints.is_empty(),
        "a cast projection cannot key a tuple:\n{}",
        complaints.join("\n")
    );
}

const TENANT_SCHEMA: &str = "
CREATE TABLE docs(id UUID PRIMARY KEY, tenant_id UUID);
CREATE TABLE m(doc_id UUID REFERENCES docs(id), tenant_id UUID, user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
";

/// The selected column is a correlation, so a second one written out in the `WHERE` makes
/// two, and one relation carries one. Probed on `PostgreSQL` 18 over a caller named on a
/// doc in another tenant: both correlations admit doc 1 alone, the selected column alone
/// admits docs 1 and 2, and the written-out one alone admits docs 1 and 3. Neither half is
/// the policy, so the pair is refused, which is what the `EXISTS` spelling already does.
#[test]
fn an_in_subquery_carrying_two_correlations_is_refused() {
    let clauses = [
        "id IN (SELECT m.doc_id FROM m WHERE m.tenant_id = docs.tenant_id \
         AND m.user_id = current_user)",
        "id = ANY (SELECT m.doc_id FROM m WHERE m.tenant_id = docs.tenant_id \
         AND m.user_id = current_user)",
        // The same policy as an EXISTS, refused today, pinned so the two cannot drift.
        "EXISTS (SELECT 1 FROM m WHERE m.doc_id = docs.id AND m.tenant_id = docs.tenant_id \
         AND m.user_id = current_user)",
    ];
    let mut complaints = Vec::new();
    for clause in clauses {
        let db = db_of(&format!(
            "{TENANT_SCHEMA}CREATE POLICY docs_members ON docs FOR SELECT USING ({clause});"
        ));
        let translator = translator(ConfidenceLevel::B);
        let outputs = translator
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps();
        let dsl = outputs.model();
        let can_select = relation_definition(&dsl, "docs", "can_select");
        if can_select.as_deref() != Some("no_access") {
            complaints.push(format!(
                "`{clause}` drops one of its two correlations, can_select is {can_select:?}"
            ));
        }
        let membership_tuples = tuples_reading_from(outputs.tuple_queries(), "\"m\"");
        if !membership_tuples.is_empty() {
            complaints.push(format!(
                "`{clause}` must emit no membership tuples, got {membership_tuples:?}"
            ));
        }
    }
    assert!(
        complaints.is_empty(),
        "a subquery correlated twice cannot become one relation:\n{}",
        complaints.join("\n")
    );
}
