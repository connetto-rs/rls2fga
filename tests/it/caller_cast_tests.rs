//! A cast between a request value and the row it is compared with.
//!
//! The model compares the value as the request sends it with the row's value rendered as
//! text. `PostgreSQL` compares whatever the casts made of both. A cast through `text` or an
//! unbounded `varchar` renders the value it is given, so both sides still compare the
//! same strings. Any other cast can rename the value (`'01'::integer` is `1`, an
//! upper-case uuid is lower-cased), so it translates only where the deployment declared
//! the request value already canonical for that type, and never on the row side.

use rls2fga::parser::sql_parser::{SessionSetting, SetPacking, SettingValue};
use rls2fga::translator::{Translation, TranslatorBuilder};
use rls2fga::types::ConfidenceLevel;
use sqlparser::ast::DataType;

use crate::support;

const TABLES: &str = "
CREATE TABLE folders(id TEXT PRIMARY KEY, owner TEXT NOT NULL);
CREATE TABLE docs(
  id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  owner_uuid UUID,
  owner_int INTEGER,
  owners UUID[],
  data JSONB,
  tenant UUID,
  folder TEXT REFERENCES folders(id));
CREATE TABLE shares(doc TEXT NOT NULL REFERENCES docs(id), user_id UUID NOT NULL,
                    PRIMARY KEY(doc, user_id));
CREATE FUNCTION text_uid() RETURNS TEXT LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.user_id'', true)';
CREATE FUNCTION int_uid() RETURNS INTEGER LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.user_id'', true)::integer';
CREATE FUNCTION renamed_uid() RETURNS TEXT LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.user_id'', true)::integer::text';
CREATE FUNCTION app_tenant() RETURNS UUID LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.tenant'', true)::uuid';
CREATE FUNCTION subjects() RETURNS SETOF UUID LANGUAGE sql STABLE
  AS 'SELECT unnest(string_to_array(current_setting(''app.subjects'', true), '',''))::uuid';
ALTER TABLE folders ENABLE ROW LEVEL SECURITY;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY folders_read ON folders FOR SELECT USING (
  owner = current_setting('app.user_id', true));
";

/// The type a `(key, cast)` pair's cast names.
fn data_type(cast: &str) -> DataType {
    match cast {
        "text" => DataType::Text,
        "integer" => DataType::Integer(None),
        "uuid" => DataType::Uuid,
        _ => panic!("the cases name only text, integer and uuid casts"),
    }
}

/// Translate `clause` as the read policy on `docs`, declaring each `(key, cast)` pair's
/// key to hold the cast's type.
fn translate(clause: &str, declared: &[(&str, &str)]) -> Translation {
    let sql = format!("{TABLES} CREATE POLICY docs_read ON docs FOR SELECT USING ({clause});");
    let db = support::deployment::db(&sql);
    let cast_of = |key: &str| {
        declared
            .iter()
            .find_map(|(declared_key, cast)| (*declared_key == key).then_some(*cast))
    };
    let settings = [
        SessionSetting::value(
            "app.user_id",
            SettingValue::Caller(match cast_of("app.user_id") {
                Some(cast) => data_type(cast),
                None => DataType::Text,
            }),
        )
        .expect("a caller name"),
        SessionSetting::value(
            "app.tenant",
            SettingValue::Scalar(match cast_of("app.tenant") {
                Some(cast) => data_type(cast),
                None => DataType::Text,
            }),
        )
        .expect("a setting name"),
        SessionSetting::value(
            "app.subjects",
            SettingValue::Set {
                element: match cast_of("app.subjects") {
                    Some(cast) => data_type(cast),
                    None => DataType::Text,
                },
                packing: SetPacking::Delimited(",".to_string()),
            },
        )
        .expect("a setting name"),
    ];
    TranslatorBuilder::new(support::deployment::deployment(settings))
        .with_min_confidence(ConfidenceLevel::B)
        .build()
        .translate(&db)
        .expect("translation plans")
}

/// Whether the read policy translated faithfully, rather than being refused into a
/// relation that denies every caller.
fn translated_faithfully(translation: Translation) -> bool {
    let diverges = translation
        .notes()
        .iter()
        .any(|note| note.severity().diverges_from_database());
    let model = translation.outputs_accepting_gaps().model();
    !diverges && !support::footgun::relation_denies(&model, "docs", "can_select")
}

/// The `(key, cast)` pairs a case declares, each naming the type its key holds.
type Declarations = &'static [(&'static str, &'static str)];

const NONE: Declarations = &[];
const USER_INTEGER: Declarations = &[("app.user_id", "integer")];
const USER_UUID: Declarations = &[("app.user_id", "uuid")];

/// Every reader of a request value, each spelling paired with the declaration that
/// decides it. A refused spelling sits beside the accepted one it differs from by one
/// cast or one declaration, so each refusal is shown to come from that cast.
const CASES: &[(&str, Declarations, bool)] = &[
    // P3, direct ownership.
    ("owner = current_setting('app.user_id', true)", NONE, true),
    ("owner = current_setting('app.user_id', true)::text", NONE, true),
    ("owner = current_setting('app.user_id', true)::varchar", NONE, true),
    ("owner = current_setting('app.user_id', true)::character varying", NONE, true),
    ("owner = current_setting('app.user_id', true)::varchar(2)", NONE, false),
    ("owner = current_setting('app.user_id', true)::integer::text", NONE, false),
    ("owner = current_setting('app.user_id', true)::integer::text", USER_INTEGER, true),
    ("owner = current_setting('app.user_id', true)::integer::text", &[("app.user_id", "text")], false),
    ("current_setting('app.user_id', true)::integer::text = owner", NONE, false),
    // A null-safe comparison with the acting role's name settles no tuple, so it
    // grades below the threshold and the clause is refused.
    ("owner IS NOT DISTINCT FROM current_user::text", NONE, false),
    ("owner_uuid IS NOT DISTINCT FROM current_user::text::uuid", NONE, false),
    ("owner = (SELECT current_setting('app.user_id', true)::integer::text)", NONE, false),
    ("owner = (SELECT current_setting('app.user_id', true))::integer::text", NONE, false),
    ("owner = (SELECT current_setting('app.user_id', true)::integer::text)", USER_INTEGER, true),
    ("owner_uuid = current_setting('app.user_id', true)::uuid", NONE, false),
    ("owner_uuid = current_setting('app.user_id', true)::UUID", USER_UUID, true),
    ("owner_int = current_setting('app.user_id', true)::integer", NONE, false),
    ("owner_int = current_setting('app.user_id', true)::integer", USER_INTEGER, true),
    // The row side has no declaration, so a cast there renames the stored value.
    ("owner::integer = current_setting('app.user_id', true)::integer", USER_INTEGER, false),
    ("owner_uuid::text = current_setting('app.user_id', true)", NONE, true),
    ("COALESCE(owner::integer, 0) = current_setting('app.user_id', true)::integer", USER_INTEGER, false),
    // The role keyword lowers to the acting role's name, so it compares as the literal it
    // names, and the same casts decide it as they decide one literal.
    ("owner = current_user", NONE, true),
    ("owner = current_user::text", NONE, true),
    ("owner_uuid = current_user::text::uuid", NONE, false),
    // The caller's accessor functions declare no cast.
    ("owner = text_uid()", NONE, true),
    ("owner_int = text_uid()::integer", USER_INTEGER, false),
    // An accessor whose body casts is the caller only where the key it reads declares it.
    ("owner_int = int_uid()", NONE, false),
    ("owner_int = int_uid()", USER_INTEGER, true),
    ("owner = renamed_uid()", NONE, false),
    ("owner = renamed_uid()", USER_INTEGER, true),
    // P11, the caller among an array's elements.
    ("current_setting('app.user_id', true)::uuid = ANY (owners)", NONE, false),
    ("current_setting('app.user_id', true)::uuid = ANY (owners)", USER_UUID, true),
    ("owners @> ARRAY[current_setting('app.user_id', true)::uuid]", NONE, false),
    ("owners @> ARRAY[current_setting('app.user_id', true)::uuid]", USER_UUID, true),
    ("owners @> ARRAY[current_setting('app.user_id', true)]::uuid[]", NONE, false),
    ("owners @> ARRAY[current_setting('app.user_id', true)]::uuid[]", USER_UUID, true),
    ("owners::text[] @> ARRAY[current_setting('app.user_id', true)]", NONE, true),
    ("owners::text[] @> ARRAY[current_setting('app.user_id', true)]", USER_UUID, true),
    // P12, the caller held in a jsonb field.
    ("data ->> 'owner' = current_setting('app.user_id', true)", NONE, true),
    ("data ->> 'owner' = current_setting('app.user_id', true)::integer::text", NONE, false),
    ("(data ->> 'owner')::uuid = current_setting('app.user_id', true)::uuid", USER_UUID, false),
    // P4, membership through a table, in both spellings.
    (
        "EXISTS (SELECT 1 FROM shares s WHERE s.doc = docs.id
                 AND s.user_id = current_setting('app.user_id', true)::uuid)",
        NONE,
        false,
    ),
    (
        "EXISTS (SELECT 1 FROM shares s WHERE s.doc = docs.id
                 AND s.user_id = current_setting('app.user_id', true)::uuid)",
        USER_UUID,
        true,
    ),
    (
        "id IN (SELECT s.doc FROM shares s
                WHERE s.user_id = current_setting('app.user_id', true)::uuid)",
        NONE,
        false,
    ),
    (
        "id IN (SELECT s.doc FROM shares s
                WHERE s.user_id = current_setting('app.user_id', true)::uuid)",
        USER_UUID,
        true,
    ),
    // P5, the parent's rule reached through a foreign key.
    (
        "EXISTS (SELECT 1 FROM folders f WHERE f.id = docs.folder
                 AND f.owner = current_setting('app.user_id', true))",
        NONE,
        true,
    ),
    (
        "EXISTS (SELECT 1 FROM folders f WHERE f.id = docs.folder
                 AND f.owner = current_setting('app.user_id', true)::integer::text)",
        NONE,
        false,
    ),
    (
        "EXISTS (SELECT 1 FROM folders f WHERE f.id = docs.folder
                 AND f.owner = current_setting('app.user_id', true)::integer::text)",
        USER_INTEGER,
        true,
    ),
    // P14 and P16, the caller's declared set.
    ("owner = ANY (string_to_array(current_setting('app.subjects', true), ','))", NONE, true),
    (
        "owner_uuid::text = ANY (string_to_array(current_setting('app.subjects', true), ','))",
        NONE,
        true,
    ),
    (
        "owner_uuid = ANY (string_to_array(current_setting('app.subjects', true), ',')::uuid[])",
        NONE,
        false,
    ),
    (
        "owner_uuid = ANY (string_to_array(current_setting('app.subjects', true), ',')::uuid[])",
        &[("app.subjects", "uuid")],
        true,
    ),
    (
        "owner::uuid = ANY (string_to_array(current_setting('app.subjects', true), ',')::uuid[])",
        &[("app.subjects", "uuid")],
        false,
    ),
    (
        "owner_uuid IN (SELECT unnest(string_to_array(current_setting('app.subjects', true), ','))::uuid)",
        NONE,
        false,
    ),
    (
        "owner_uuid IN (SELECT unnest(string_to_array(current_setting('app.subjects', true), ','))::uuid)",
        &[("app.subjects", "uuid")],
        true,
    ),
    ("owner_uuid IN (SELECT subjects())", NONE, false),
    ("owner_uuid IN (SELECT subjects())", &[("app.subjects", "uuid")], true),
    // P15 and P17, the caller's declared single value.
    ("tenant::text = current_setting('app.tenant', true)", NONE, true),
    ("tenant = current_setting('app.tenant', true)::uuid", NONE, false),
    ("tenant = current_setting('app.tenant', true)::uuid", &[("app.tenant", "uuid")], true),
    ("tenant = app_tenant()", NONE, false),
    ("tenant = app_tenant()", &[("app.tenant", "uuid")], true),
    // A constant compared with a value cast away from text is coerced to that type too.
    ("current_setting('app.tenant', true) = '7'", NONE, true),
    ("current_setting('app.tenant', true)::integer = '7'", &[("app.tenant", "integer")], false),
    ("current_setting('app.tenant', true) = '07'::integer::text", NONE, false),
    // The caller's presence beside a rule, which a cast turns into a filter of its own.
    (
        "owner = current_setting('app.user_id', true)
         AND current_setting('app.user_id', true)::integer IS NOT NULL",
        NONE,
        false,
    ),
];

#[test]
fn every_request_reader_refuses_a_cast_that_can_rename_the_value() {
    let wrong: Vec<String> = CASES
        .iter()
        .filter(|(clause, declared, faithful)| {
            translated_faithfully(translate(clause, declared)) != *faithful
        })
        .map(|(clause, declared, faithful)| {
            let verdict = if *faithful { "refused" } else { "translated" };
            format!("{verdict} `{clause}` declaring {declared:?}")
        })
        .collect();
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// P2, a role function handed the caller.
#[test]
fn a_role_function_takes_the_caller_only_through_a_declared_cast() {
    let schema = std::fs::read_to_string("tests/fixtures/role_in_list/input.sql")
        .expect("fixture schema")
        .replace(
            "get_owner_role(auth_current_user_id(), owner_id)",
            "get_owner_role(current_setting('app.user_id', true)::uuid, owner_id)",
        );
    let registry = std::fs::read_to_string("tests/fixtures/role_in_list/function_registry.json")
        .expect("fixture registry");
    let db = support::deployment::db(&schema);
    let translate = |value: SettingValue| {
        TranslatorBuilder::new(support::deployment::deployment([SessionSetting::value(
            "app.user_id",
            value,
        )
        .expect("a caller name")]))
        .with_min_confidence(ConfidenceLevel::B)
        .with_registry_json(&registry)
        .expect("registry loads")
        .build()
        .translate(&db)
        .expect("translation plans")
    };
    let refused = |translation: &Translation| {
        translation
            .notes()
            .iter()
            .any(|note| note.severity().diverges_from_database())
    };

    assert!(refused(&translate(SettingValue::Caller(DataType::Text))));
    assert!(!refused(&translate(SettingValue::Caller(DataType::Uuid))));
}

/// A refusal names the declaration that would let the cast through, whether the cast is
/// written in the policy or in the body of the accessor it calls.
#[test]
fn a_refusal_names_the_type_to_declare() {
    use rls2fga::classifier::patterns::{PatternClass, UnclassifiedExpr};

    for clause in [
        "owner = current_setting('app.user_id', true)::integer::text",
        "owner_int = int_uid()",
    ] {
        let sql = format!("{TABLES} CREATE POLICY docs_read ON docs FOR SELECT USING ({clause});");
        let db = support::deployment::db(&sql);
        let classified = TranslatorBuilder::new(support::deployment::deployment([
            support::deployment::caller("app.user_id"),
        ]))
        .build()
        .classify(&db);
        let pattern = classified
            .iter()
            .find(|policy| policy.name() == "docs_read")
            .and_then(|policy| policy.using_classification())
            .map(|classified| &classified.pattern);
        let Some(PatternClass::Unknown(UnclassifiedExpr { reason, .. })) = pattern else {
            panic!("`{clause}` must be refused, got {pattern:?}");
        };
        assert!(
            reason.contains("declare app.user_id in the deployment as holding integer"),
            "`{clause}`: {reason}"
        );
    }
}

#[cfg(all(not(target_os = "windows"), feature = "client"))]
mod parity {
    use rls2fga::parser::sql_parser::{SessionSetting, SetPacking, SettingValue};
    use rls2fga::types::ActionStatement;
    use sqlparser::ast::DataType;

    use super::data_type;
    use super::support::parity::{
        assert_agrees, assert_disclosed_where_noted, assert_postgres, run, run_disclosing, Cluster,
        ParityCase, Principal,
    };

    const LOWER: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const UPPER: &str = "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA";

    const SCHEMA: &str = "
CREATE TABLE folders(id TEXT PRIMARY KEY, owner TEXT NOT NULL);
CREATE TABLE docs(
  id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  owner_uuid UUID NOT NULL,
  owners UUID[] NOT NULL,
  data JSONB NOT NULL,
  tenant UUID NOT NULL,
  folder TEXT NOT NULL REFERENCES folders(id));
CREATE TABLE shares(doc TEXT NOT NULL REFERENCES docs(id), user_id UUID NOT NULL,
                    PRIMARY KEY(doc, user_id));
CREATE FUNCTION uuid_uid() RETURNS UUID LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.user_id'', true)::uuid';
ALTER TABLE folders ENABLE ROW LEVEL SECURITY;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY folders_read ON folders FOR SELECT USING (true);
";

    /// `d01` is owned by `'01'` and by the lower-case uuid, `d1` by `'1'` and another uuid.
    const SEED: &[&str] = &[
        "INSERT INTO folders VALUES ('f01', '01'), ('f1', '1');",
        "INSERT INTO docs VALUES
           ('d01', '01', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
            '{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}', '{\"owner\": \"01\"}',
            'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'f01'),
           ('d1', '1', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
            '{bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}', '{\"owner\": \"1\"}',
            'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'f1');",
        "INSERT INTO shares VALUES ('d01', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');",
        "CREATE ROLE app_reader LOGIN; GRANT SELECT ON folders, docs, shares TO app_reader;",
    ];

    /// One caller sending `value` as its identity, its tenant and its one-element set.
    /// The tenant travels in the check's `settings` map the harness builds from the
    /// session, the set in its own list parameter.
    fn caller(value: &str) -> Principal {
        let mut principal = Principal::with_setting(value, "app_reader", "app.user_id", value)
            .with_context(serde_json::json!({ "app_subjects": [value] }));
        principal
            .session
            .push(("app.tenant".to_string(), value.to_string()));
        principal
            .session
            .push(("app.subjects".to_string(), value.to_string()));
        principal
    }

    /// The three request values the case declares, the `(key, cast)` pair among them
    /// declaring its key to hold the cast's type.
    fn settings(declared: Option<(&str, &str)>) -> Vec<SessionSetting> {
        let cast_of = |key: &str| {
            declared
                .filter(|(declared_key, _)| *declared_key == key)
                .map(|(_, cast)| cast)
        };
        vec![
            SessionSetting::value(
                "app.user_id",
                SettingValue::Caller(match cast_of("app.user_id") {
                    Some(cast) => data_type(cast),
                    None => DataType::Text,
                }),
            )
            .expect("a caller name"),
            SessionSetting::value(
                "app.tenant",
                SettingValue::Scalar(match cast_of("app.tenant") {
                    Some(cast) => data_type(cast),
                    None => DataType::Text,
                }),
            )
            .expect("a setting name"),
            SessionSetting::value(
                "app.subjects",
                SettingValue::Set {
                    element: match cast_of("app.subjects") {
                        Some(cast) => data_type(cast),
                        None => DataType::Text,
                    },
                    packing: SetPacking::Delimited(",".to_string()),
                },
            )
            .expect("a setting name"),
        ]
    }

    fn case(
        name: &str,
        clause: &str,
        callers: &[&str],
        declared: Option<(&str, &str)>,
    ) -> ParityCase {
        let schema =
            format!("{SCHEMA} CREATE POLICY docs_read ON docs FOR SELECT USING ({clause});");
        ParityCase::reading(
            name,
            &schema,
            SEED,
            callers.iter().map(|value| caller(value)).collect(),
        )
        .with_settings(settings(declared))
    }

    /// Spellings whose cast goes through `integer`, which drops the leading zero of `'01'`.
    const THROUGH_INTEGER: &[(&str, &str)] = &[
        (
            "p3-integer",
            "owner = current_setting('app.user_id', true)::integer::text",
        ),
        (
            "p12-integer",
            "data ->> 'owner' = current_setting('app.user_id', true)::integer::text",
        ),
        (
            "p5-integer",
            "EXISTS (SELECT 1 FROM folders f WHERE f.id = docs.folder
                     AND f.owner = current_setting('app.user_id', true)::integer::text)",
        ),
    ];

    /// Spellings whose cast goes through `uuid`, which lower-cases the caller, each with the
    /// key its declaration goes on.
    const THROUGH_UUID: &[(&str, &str, &str)] = &[
        (
            "p3-uuid",
            "owner_uuid = current_setting('app.user_id', true)::uuid",
            "app.user_id",
        ),
        (
            "p11-uuid",
            "current_setting('app.user_id', true)::uuid = ANY (owners)",
            "app.user_id",
        ),
        (
            "p4-uuid",
            "EXISTS (SELECT 1 FROM shares s WHERE s.doc = docs.id
                     AND s.user_id = current_setting('app.user_id', true)::uuid)",
            "app.user_id",
        ),
        ("accessor-uuid", "owner_uuid = uuid_uid()", "app.user_id"),
        (
            "p15-uuid",
            "tenant = current_setting('app.tenant', true)::uuid",
            "app.tenant",
        ),
        (
            "p14-uuid",
            "owner_uuid = ANY (string_to_array(current_setting('app.subjects', true), ',')::uuid[])",
            "app.subjects",
        ),
    ];

    /// Undeclared, `'01'` would have been granted `d01`, which `PostgreSQL` hides, so the
    /// translation refuses and discloses it. Declared, a caller sending canonical integers
    /// agrees with the database.
    #[tokio::test]
    #[ignore = "requires Docker, PostgreSQL and OpenFGA"]
    async fn an_integer_cast_is_refused_until_declared() {
        tokio::time::timeout(std::time::Duration::from_secs(300), async {
            let cluster = Cluster::start().await;
            for (name, clause) in THROUGH_INTEGER {
                let refused = case(&format!("{name}-refused"), clause, &["01", "1"], None);
                let run_refused = run_disclosing(&cluster, &refused).await;
                assert_postgres(
                    &refused,
                    &run_refused,
                    "01",
                    "docs:d01",
                    ActionStatement::Select,
                    false,
                );
                assert_postgres(
                    &refused,
                    &run_refused,
                    "01",
                    "docs:d1",
                    ActionStatement::Select,
                    true,
                );
                assert_disclosed_where_noted(&refused, &run_refused);

                for from_rows in [false, true] {
                    let mut declared = case(
                        &format!("{name}-declared-rows-{from_rows}"),
                        clause,
                        &["1"],
                        Some(("app.user_id", "integer")),
                    );
                    declared.loading_from_rows = from_rows;
                    let run_declared = run(&cluster, &declared).await;
                    assert_postgres(
                        &declared,
                        &run_declared,
                        "1",
                        "docs:d1",
                        ActionStatement::Select,
                        true,
                    );
                    assert_postgres(
                        &declared,
                        &run_declared,
                        "1",
                        "docs:d01",
                        ActionStatement::Select,
                        false,
                    );
                    assert_agrees(&declared, &run_declared);
                }
            }
        })
        .await
        .expect("integer casts must finish within 300 seconds");
    }

    /// Undeclared, the upper-case caller sees `d01` in `PostgreSQL` while the model would
    /// have looked for its upper-case spelling, so the translation refuses and discloses
    /// it. Declared, a caller sending the canonical lower case agrees with the database.
    #[tokio::test]
    #[ignore = "requires Docker, PostgreSQL and OpenFGA"]
    async fn a_uuid_cast_is_refused_until_declared() {
        tokio::time::timeout(std::time::Duration::from_secs(300), async {
            let cluster = Cluster::start().await;
            for (name, clause, key) in THROUGH_UUID {
                let refused = case(&format!("{name}-refused"), clause, &[LOWER, UPPER], None);
                let run_refused = run_disclosing(&cluster, &refused).await;
                assert_postgres(
                    &refused,
                    &run_refused,
                    UPPER,
                    "docs:d01",
                    ActionStatement::Select,
                    true,
                );
                assert_disclosed_where_noted(&refused, &run_refused);

                for from_rows in [false, true] {
                    let mut declared = case(
                        &format!("{name}-declared-rows-{from_rows}"),
                        clause,
                        &[LOWER],
                        Some((key, "uuid")),
                    );
                    declared.loading_from_rows = from_rows;
                    let run_declared = run(&cluster, &declared).await;
                    assert_postgres(
                        &declared,
                        &run_declared,
                        LOWER,
                        "docs:d01",
                        ActionStatement::Select,
                        true,
                    );
                    assert_postgres(
                        &declared,
                        &run_declared,
                        LOWER,
                        "docs:d1",
                        ActionStatement::Select,
                        false,
                    );
                    assert_agrees(&declared, &run_declared);
                }
            }
        })
        .await
        .expect("uuid casts must finish within 300 seconds");
    }

    /// The row's side takes no declaration, so a cast there stays refused. `'01'::integer`
    /// is `1`, so the caller `'1'` owns both rows in `PostgreSQL`.
    #[tokio::test]
    #[ignore = "requires Docker, PostgreSQL and OpenFGA"]
    async fn a_row_side_cast_stays_refused_when_the_caller_is_declared() {
        tokio::time::timeout(std::time::Duration::from_secs(300), async {
            let cluster = Cluster::start().await;
            let refused = case(
                "row-side-integer",
                "owner::integer = current_setting('app.user_id', true)::integer",
                &["1"],
                Some(("app.user_id", "integer")),
            );
            let run_refused = run_disclosing(&cluster, &refused).await;
            assert_postgres(
                &refused,
                &run_refused,
                "1",
                "docs:d01",
                ActionStatement::Select,
                true,
            );
            assert_postgres(
                &refused,
                &run_refused,
                "1",
                "docs:d1",
                ActionStatement::Select,
                true,
            );
            assert_disclosed_where_noted(&refused, &run_refused);
        })
        .await
        .expect("the row-side cast must finish within 300 seconds");
    }
}
