# rls2fga

[![CI](https://github.com/connetto-rs/rls2fga/actions/workflows/ci.yml/badge.svg)](https://github.com/connetto-rs/rls2fga/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/connetto-rs/rls2fga/graph/badge.svg)](https://codecov.io/gh/connetto-rs/rls2fga)
[![License](https://img.shields.io/github/license/connetto-rs/rls2fga)](https://github.com/connetto-rs/rls2fga/blob/main/LICENSE)

Convert `PostgreSQL` [Row Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) policies into an [OpenFGA](https://openfga.dev/docs) authorization model, plus the SQL that fills its relationship tuples from your database.

Each `USING` and `WITH CHECK` expression is classified against the patterns below. What is recognised becomes types and relations, what is not is denied and reported, so the model is never wider than the policy.

> [!WARNING]
> Not on crates.io yet, pending a `sqlparser` release with `no_std` fixes.

## Usage

Describe the deployment your requests run as, parse a schema that declares its roles, plan a translation, then ask it for each output. The plan is built once and every output is rendered from it.

```rust
use rls2fga::generator::tuple_generator::format_tuples;
use rls2fga::parser::sql_parser::{parse_schema, Deployment, SessionSetting, SettingValue};
use rls2fga::translator::TranslatorBuilder;
use rls2fga::types::ConfidenceLevel;
use sqlparser::ast::DataType;

let sql = "
    CREATE ROLE authenticator LOGIN NOINHERIT;
    CREATE ROLE web_user NOLOGIN;
    GRANT web_user TO authenticator WITH INHERIT FALSE, SET TRUE;
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

let db = parse_schema(sql).expect("parse error");
let caller = SessionSetting::value("app.current_user_id", SettingValue::Caller(DataType::Uuid))
    .expect("a custom setting name");
let deployment = Deployment::new("authenticator", ["web_user"], [caller])
    .expect("one acting role");
let translation = TranslatorBuilder::new(deployment)
    .with_min_confidence(ConfidenceLevel::B)
    .build()
    .translate(&db)
    .expect("schema should plan");
let outputs = translation.outputs().expect("every clause translated");

println!("{}", outputs.model());
println!("{}", format_tuples(&outputs.tuple_queries()));

for note in outputs.notes() {
    eprintln!("[{}] {}: {note}", note.severity(), note.subject());
}
```

`outputs()` refuses every note whose severity `diverges_from_database()`, including `Unhandled`, `Partial` and `BelowThreshold`, and `DivergentTranslation::notes()` names each gap. `outputs_accepting_gaps()` deliberately accepts models that may grant what the database denies or deny what it grants. `min_confidence` sets the bar (`A` fully translated, `B` composed or row-decided, `C` a relationship with an unenforced attribute guard, `D` unrecognised), and `Outputs::report()` lists dropped clauses, with dropped `PERMISSIVE` clauses granting nothing and dropped `RESTRICTIVE` clauses becoming `no_access`.

The `sql_traits` `Deployment` names the role a request logs in as, the roles it acts as, and every session setting a policy may read, whether the caller's identity, one value, or a set joined by a delimiter or packed as a JSON array, each with its type and whether a request may leave it unset. A setting it does not declare is refused wherever a policy reads it, and so is a set split on another delimiter than the declared one. The schema has to declare the deployment's roles.

The model compares the caller as sent, while `PostgreSQL` compares whatever a cast made of it, and `'01'::integer` is `1`. Any cast but `text` or an unbounded `varchar` on a request value or on the row it meets is therefore refused, unless the deployment declares the setting in that type, which promises that every request sends it in the type's canonical form, as the `::uuid` above does.

## Output

The example above yields this model. Only `SELECT` has a policy, so every other command denies through `no_access`, whose only allowed subject is the `nobody` type no tuple ever names. `acting_web_user from request_gate` admits only checks that send `(user:<subject>, usage, pg_role:web_user)`, the role the deployment acts as. Apply it with `fga model write --store-id "$FGA_STORE_ID" --file model.fga`.

```fga
model
  schema 1.1

type user

type documents
  relations
    define no_access: [nobody]
    define owner: [user]
    define request_gate: [request_gate]
    define can_delete: no_access
    define can_insert: no_access
    define can_select: owner and acting_web_user from request_gate
    define can_select_for_update: can_update
    define can_update: no_access
    define can_update_without_reading: can_update

type nobody

type pg_role
  relations
    define usage: [user]

type request_gate
  relations
    define acting_web_user: [pg_role#usage]
```

Beside it comes one query per relation a permission can reach, so a table that denies everything yields nothing to load. The prelude pins the session's text rendering, and the `CASE` hex-escapes any key value the target would refuse, so every row becomes one `OpenFGA` id.

```sql
SET TIME ZONE 'UTC';
SET DateStyle = 'ISO, MDY';
SET bytea_output = 'hex';

-- User ownership (owner_id references users)
SELECT 'documents:' || CASE WHEN "id"::text COLLATE "C" ~ '^[A-Za-z0-9._@-]+$' THEN "id"::text ELSE '~' || encode(convert_to("id"::text, 'UTF8'), 'hex') END AS object, 'owner' AS relation, 'user:' || CASE WHEN "owner_id"::text COLLATE "C" ~ '^[A-Za-z0-9._@-]+$' THEN "owner_id"::text ELSE '~' || encode(convert_to("owner_id"::text, 'UTF8'), 'hex') END AS subject
FROM "public"."documents"
WHERE "owner_id" IS NOT NULL
AND "id" IS NOT NULL;

-- documents admits requests acting as PostgreSQL role 'web_user', which the deployment decides rather than any row
SELECT 'request_gate:documents' AS object, 'acting_web_user' AS relation, 'pg_role:web_user' || '#usage' AS subject;

-- Every documents row is judged by the scope documents
SELECT 'documents:' || CASE WHEN "id"::text COLLATE "C" ~ '^[A-Za-z0-9._@-]+$' THEN "id"::text ELSE '~' || encode(convert_to("id"::text, 'UTF8'), 'hex') END AS object, 'request_gate' AS relation, 'request_gate:documents' AS subject
FROM "public"."documents"
WHERE "id" IS NOT NULL;
```

Every query projects `object`, `relation` and `subject`. One whose `TupleQuery::condition` is `Some` adds `condition` and `context`, a `jsonb` object holding the condition's row-supplied parameters. `Outputs::record_from_tuple_row` reads a row back as a `Record`, refusing one the model holds no such fact for, and `generator::records::records_from_row` produces the same records from a row's values with no database at all.

Running the SQL and writing the tuples are yours: the crate keeps no database handle. The model is the exception, `client::write_authorization_model` writes it to a running server over a client you built.

A model `OpenFGA` would refuse to store is a translation error. `translate` returns `PlanningError::ModelBoundExceeded`, naming the bound, the item and both numbers, for every bound the `openfga/api` protobuf declares, such as 25 conditions, 512-byte condition expressions and 50-character names. Limits the server sets in its own configuration cannot be known here, so `Outputs::type_count` and, with `client`, `Outputs::model_size_in_bytes` report what to compare against `maxTypesPerAuthorizationModel` (100 by default) and `maxAuthorizationModelSizeInBytes` (256 KiB).

## Cargo features

`std` is on by default and carries the file output surface (`Outputs::write`). Without it the crate builds on `no_std` plus `alloc`, verified against `thumbv7em-none-eabi`, with the whole pipeline intact. `client` adds the model writer and implies `std`.

## Supported patterns

A report names a pattern by its number, so `P4 (EXISTS members)` beside a TODO points at a row here.

| # | Pattern | Shape | Mapping |
| --- | --- | --- | --- |
| P1 | `NumericThreshold` | `role_fn(user, resource) >= N` | Hierarchical relations from the level |
| P2 | `RoleNameInList` | `role_fn(user, resource) IN ('viewer', ...)` | One relation per role name |
| P3 | `DirectOwnership` | `owner_id = current_user_id()` | `owner: [user]` |
| P4 | `ExistsMembership` | `EXISTS (SELECT 1 FROM members ...)`, `IN`, `= ANY` | Source-specific membership relations |
| P5 | `ParentInheritance` | FK join carrying a parent-side rule | `owner from parent`, gated by the parent's `can_select` |
| P6 | `BooleanFlag` | `is_public = TRUE` | `[user:*]` |
| P7 | `AbacAnd` | Relationship check `AND` attribute guard | Relationship half only, guard as a TODO |
| P8 | `Composite` | `expr OR expr`, `expr AND expr` | Union, intersection |
| P9 | `AttributeCondition` | `status IN ('active', 'pending')`, `team_id IS NULL`, `expires_at > now()` | A row-decided value guards the tuple query, a clock-decided one becomes a condition |
| P10 | `ConstantBool` | `TRUE`, `FALSE` | `[user:*]`, or no access |
| P11 | `ArrayMembership` | `current_setting('app.user_id') = ANY (editors)` | Relation named after the column, one tuple per element |
| P12 | `JsonbFieldOwnership` | `data ->> 'owner' = current_user_id()` | `owner: [user]`, read from the field |
| P13 | `UncorrelatedMembership` | `EXISTS (SELECT 1 FROM staff WHERE user_id = current_user_id())` | One holder object with source-specific membership relations |
| P14 | `RowValueInCallerSet` | `owner = ANY(string_to_array(current_setting('app.subjects', true), ','))` | A gate asking whether the caller's list holds the row's value |
| P15 | `RowValueEqualsCallerScalar` | `tenant_id = current_setting('app.tenant_id')::uuid` | The same gate, equality against the caller's value |
| P16 | `ConstantInCallerSet` | `'admin' = ANY(string_to_array(current_setting('app.roles', true), ','))` | A test of the caller's list, held once per table, see below |
| P17 | `CallerScalarEqualsConstant` | `(SELECT auth.jwt() ->> 'aal') = 'aal2'` | A test of the caller's value, held once per table, see below |
| P18 | `MembershipInCallerSet` | `EXISTS (SELECT 1 FROM shares s WHERE s.parent_id = t.id AND s.viewer = ANY(...))` | The gate on each share row, reached through the same parent P4 bridges to |
| P19 | `IndirectMembership` | Nested `EXISTS` or an inner `JOIN` through a closure table | `member from ancestor`, with both hops referencing the same declared owner key |
| P20 | `DeclaredHelper` | `project_id = ANY (ARRAY(SELECT authz.projects_with('read')))` | One relation per role and per call, `projects_with_read from projects` |
| - | `MembershipExclusion` | Positive grant `AND NOT EXISTS (...)`, caller `NOT IN (...)`, caller `<> ALL (...)` | Grant `but not blocked`, with independent relations per blocklist |
| - | `Unknown` | Anything else | Denied, with a TODO, unless an oracle classifies it |

Blocklist subqueries must be correlated caller-identity memberships over tables with no own or inherited row-level security. `NOT IN` and `<> ALL` require a provably non-null projected column. A negative-only `RESTRICTIVE` clause subtracts from the action's existing grants, while standalone permissive negation and caller-set blocklists are refused.

`current_user`, `current_role` and `user` name the role a request acts as, and `session_user` the role it logs in as, so each reads as the name the deployment gives that role and never as the caller. Policies are read once per acting role, so a comparison such as `current_user = 'reader'` holds for that role and fails for every other. `pg_has_role` is decided by the roles and grants the schema declares, before any row is read.

## Gates that read only the request

A clause built from P16, P17 and constants has the same answer for every row, so it is stated once per table. It is first reduced to a normal form, which flattens nested `AND` and `OR`, drops repeated or subsumed arms and folds constants, so two spellings of one gate become one relation. Each constant it tests is one tuple on the `request_gate` object named after the table (`request_gate:docs`), and the `AND` and `OR` between them are written in the model. Each row carries one `request_gate` link to that object, however many gates the table has.

Every test of one kind shares one condition (`required_value in app_bot_list`), so the model declares one condition per distinct guard rather than per table or policy. `OpenFGA` limits each condition evaluation by cost (`maxConditionEvaluationCost`, 100 by default), which on `OpenFGA` 1.11 stops a test at a list of about 90 fifteen-character entries. Testing several constants in one expression would divide that limit between them, which is why each constant gets its own tuple. The relation report states such a gate as `RowDecision::Request`, which the check context decides without any record.

## What the crate refuses

An unrecognised expression is denied rather than guessed at, which is safe but narrower than the policy. Implement `PolicyOracle` and call `consult_oracle` to answer for your own shapes: each refusal is offered with its reason, and bailing is the default, so an oracle implementing nothing changes nothing. Use it rather than rewriting classifications yourself, since a refusal nests inside composites and every enclosing pattern has to be regraded. `classifier::oracle` documents the traps with a worked example.

Two refusals are deliberate. Reading the body of a `SECURITY DEFINER` function would defeat the marking, since it sees rows the caller cannot. A jsonb field read by position, `data -> 0 ->> 'owner'`, would name a permission after an offset that unrelated code can repoint. Both reach you through the oracle.

A definer helper you declare with `TranslatorBuilder::with_declared_helpers` is the exception. It has to be a `STABLE` SQL function returning `SETOF` one type, with a pinned `search_path`, owned by a role the schema declares that holds `SELECT` on what it reads and is exempt from those tables' policies, its body a `UNION` of the caller's grant rows and of rows whose parent another declared helper returns. Its owner then reads what the tuple queries read. Each value of a grant table's role column, its one `NOT NULL` column a `CHECK` closes to literals, becomes a relation, each call a relation on the table whose keys it returns, and each parent arm `<call> from <parent>`. A helper outside that shape is refused naming why. Declaring one asserts that every role a request runs as may execute it, since a caller lacking `EXECUTE` gets an error where the model grants.

A column with no foreign key, such as an `owner` that may name a team or a project, names the rows of the one table the set it is compared with covers. Each level it is compared with becomes a parent of its own, so `owner = ANY (ARRAY(SELECT authz.teams_with('admin'))) OR owner = ANY (ARRAY(SELECT authz.projects_with('admin')))` reads as `teams_with_admin from teams or projects_with_admin from projects`, each parent loaded from `owner`. A key value two levels share admits through either, as it does in `PostgreSQL`.

## Reads gate the other commands

Naming a row to change means reading it, so `can_update` and `can_delete` intersect `can_select`, while an `UPDATE` naming no row is `can_update_without_reading`. Plain `INSERT` reads nothing, but `RETURNING` a column and naming an `ON CONFLICT` target both read the new row back, which is `can_insert_returning`. An `UPDATE` also applies the `SELECT` policies to the row it writes, so `can_update_check` intersects `can_select` too, and an `UPDATE` naming no row judges the row it writes with `can_update_without_reading_check` where that differs. `INSERT ... ON CONFLICT DO UPDATE` is judged by `can_insert_returning`, `can_update_using` and `can_update_check` together. A locking read (`FOR UPDATE` and friends) also applies the `UPDATE` policies, so check `can_select_for_update` rather than `can_select`. A policy expression reads every table it names, so an inherited parent rule intersects the parent's `can_select` and a membership table granting no reads denies outright.

Membership tables whose permissive read policies all use `USING (true)` and apply to `PUBLIC` need no caveat when their restrictive read policies are absent or constant `true`. Supported restrictive gates using only literals and settings the deployment declares are `AND`ed onto the membership arm and require those settings in each check context. A membership table whose read policies reach only some acting roles grants through it to those roles alone. Row-dependent membership rules retain `MembershipTableGuarded`.

A residual such as `s.weight > (SELECT avg(weight) FROM paper_shares)` may read a table gated that way too. When the gate holds the caller sees what the loader saw, and when it fails the table reads empty, so the residual is accepted only where an empty table makes it false (`avg` of nothing is `NULL`, `count` of nothing fails `> 0`), and the grant is `AND`ed with the gate. `count(*) = 0` and `NOT EXISTS` stay refused.

Membership tuple relations are isolated by table, correlation, user column, predicates and condition inputs. Parent and share-row bridges are isolated by the columns they traverse.

## Runtime data you have to supply

Every check states the role the request acts as with the contextual tuple `(user:<subject>, usage, pg_role:<role>)`. Which policies reach that role, their `TO` lists, an owner or `BYPASSRLS` exemption and a recursion `PostgreSQL` raises on are answered per acting role by `sql_traits`' `row_security`, and every action relation is a union of one branch per acting role, joined as `acting_<role> from request_gate` through the table's `request_gate` object. The tuple queries write that object's constant `(request_gate:<table>, acting_<role>, pg_role:<role>#usage)`, so no role fact is loaded by hand. The relation report states that join as `RequestPredicate::ActsAs`, which the check's kind decides without any record.

Every value a policy reads from a setting other than the caller travels in the one `settings` parameter, a map of the value's text keyed by its parameter name, after the setting and field, `app.tenant_id` as `app_tenant_id`. Every check carries the map, empty when nothing is set, and a request that leaves a setting the deployment says may be unset omits its key, never `''` or an empty list. `PostgreSQL` reads such a setting as `NULL` on a fresh connection and as `''` once a transaction-local value has ended, and the model answers as `NULL` does, which admits least. Where `''` would admit rows, an `UnsetSettingReadAsEmpty` note names the comparison. A set keeps its own `list<string>` parameter beside the map, which the check carries as before.

A guard against statement time such as `expires_at > now()` cannot be a tuple, since whatever it decided when written stays decided. It becomes an `OpenFGA` condition instead: the row's value travels with the tuple and every check must carry the time in its context under `request_time`, renamed by `TranslatorBuilder::with_request_time_parameter`, which refuses `settings`, the map's own name. A day or month window, `current_date` and `localtimestamp` read the clock in the session `TimeZone`, which CEL cannot, so each becomes a parameter of its own such as `request_time_minus_1_day`. So does a `date` or `timestamp` literal compared with a `timestamptz` column, which `PostgreSQL` converts in that zone, as `request_time_at_2026_01_01`. `Translation::clock_context` computes every clock parameter of one check from the instant and the zone the request runs in.

`PostgreSQL` stores a policy's `timestamptz` literal as the instant it reads in the `TimeZone` of the session that created the policy, so `parse_schema_in_time_zone` takes the zone the migration ran in. Under `parse_schema` such a literal, written without an offset before any `SET TIME ZONE` in the script, has no value, and its policy falls closed. A `money` literal such as `'$10.00'::money` is parsed by `lc_monetary` instead, so its policy falls closed until `TranslatorBuilder::with_monetary_locale` names the locale the schema was written in, and every tuple query then carries it as `monetary_locale` for the loader to set.

## License

Licensed under the MIT License. See `LICENSE`.
