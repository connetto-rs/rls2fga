//! Two columns of the checked row compared with each other, against `PostgreSQL` 17 and 18
//! with both tuple loaders.

#![cfg(all(not(target_os = "windows"), feature = "client"))]

use core::time::Duration;

use rls2fga::types::ActionStatement;
use sqlparser::ast::DataType;

use crate::support;
use crate::support::parity::{assert_agrees, assert_postgres, Cluster, ParityCase, Principal};

const ALICE: &str = "aaaaaaaa-0000-0000-0000-000000000001";
const BOB: &str = "bbbbbbbb-0000-0000-0000-000000000002";
const ALICE_ORGANIZATION: &str = "a0000000-0000-0000-0000-00000000000a";
const BOB_ORGANIZATION: &str = "b0000000-0000-0000-0000-00000000000b";
const NESTED_RESOURCE: &str = "c0000000-0000-0000-0000-00000000000c";

/// Grants on resources whose root is the organization, a founder reading the grant naming
/// themself on their organization's root, and ranges any caller reads where their bounds
/// are ordered, or reversed under two different labels.
const COMPARED: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE organizations (id UUID PRIMARY KEY, created_by_id UUID NOT NULL);
CREATE TABLE resources (id UUID PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES organizations (id), UNIQUE (organization_id, id));
CREATE TABLE grants (
  resource_id UUID NOT NULL,
  organization_id UUID NOT NULL,
  grantee_id UUID NOT NULL,
  PRIMARY KEY (resource_id, grantee_id),
  FOREIGN KEY (organization_id, resource_id) REFERENCES resources (organization_id, id)
);
CREATE TABLE ranges (id TEXT PRIMARY KEY, low INTEGER, high BIGINT, label TEXT, other_label TEXT);
GRANT SELECT ON organizations TO authz_owner;
CREATE FUNCTION authz.caller_id() RETURNS UUID LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = '' AS $$ SELECT NULLIF(current_setting('app.user_id', true), '')::uuid $$;
CREATE FUNCTION authz.founded_organizations() RETURNS SETOF UUID LANGUAGE sql STABLE
  SECURITY DEFINER SET search_path = '' AS $$
  SELECT organization.id FROM public.organizations organization
  WHERE organization.created_by_id = authz.caller_id() $$;
ALTER FUNCTION authz.caller_id() OWNER TO authz_owner;
ALTER FUNCTION authz.founded_organizations() OWNER TO authz_owner;
ALTER TABLE grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE ranges ENABLE ROW LEVEL SECURITY;
CREATE POLICY grants_founder ON grants FOR SELECT
  USING (resource_id = organization_id AND grantee_id = (SELECT authz.caller_id())
    AND organization_id = ANY (ARRAY(SELECT authz.founded_organizations())));
CREATE POLICY ranges_ordered ON ranges FOR SELECT USING (low <= high);
CREATE POLICY ranges_relabelled ON ranges FOR SELECT
  USING (label <> other_label AND high < low);
";

const HELPERS: &str = r#"{ "authz.founded_organizations": { "kind": "declared_helper" } }"#;

fn caller(subject: &str) -> Principal {
    Principal::with_setting(subject, "app_reader", "app.user_id", subject)
}

/// Alice founded one organization and Bob the other. Each is granted on both roots, and Alice
/// on a resource nested in hers. Ranges hold every order of their bounds and a NULL in each
/// compared column.
fn compared_case(major: &str, loading_from_rows: bool) -> ParityCase {
    let seed = format!(
        "INSERT INTO organizations VALUES ('{ALICE_ORGANIZATION}', '{ALICE}'),
           ('{BOB_ORGANIZATION}', '{BOB}');
         INSERT INTO resources VALUES ('{ALICE_ORGANIZATION}', '{ALICE_ORGANIZATION}'),
           ('{BOB_ORGANIZATION}', '{BOB_ORGANIZATION}'),
           ('{NESTED_RESOURCE}', '{ALICE_ORGANIZATION}');
         INSERT INTO grants VALUES
           ('{ALICE_ORGANIZATION}', '{ALICE_ORGANIZATION}', '{ALICE}'),
           ('{ALICE_ORGANIZATION}', '{ALICE_ORGANIZATION}', '{BOB}'),
           ('{BOB_ORGANIZATION}', '{BOB_ORGANIZATION}', '{ALICE}'),
           ('{BOB_ORGANIZATION}', '{BOB_ORGANIZATION}', '{BOB}'),
           ('{NESTED_RESOURCE}', '{ALICE_ORGANIZATION}', '{ALICE}');
         INSERT INTO ranges VALUES
           ('equal', 3, 3, 'a', 'a'), ('ascending', 3, 10, 'a', 'a'),
           ('descending', 10, 3, 'a', 'b'), ('descending_same', 10, 3, 'a', 'a'),
           ('null_low', NULL, 3, 'a', 'b'), ('null_high', 3, NULL, 'a', 'b'),
           ('null_label', 10, 3, NULL, 'b')"
    );
    let mut case = ParityCase::reading(
        &format!(
            "column-comparison-pg{major}{}",
            if loading_from_rows { "-rows" } else { "" }
        ),
        COMPARED,
        &[
            &seed,
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON grants, ranges TO app_reader;
             GRANT USAGE ON SCHEMA authz TO app_reader;
             REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO app_reader",
        ],
        vec![
            caller(ALICE),
            caller(BOB),
            Principal::as_role("anonymous", "app_reader"),
        ],
    )
    .with_settings([
        support::deployment::typed_caller("app.user_id", DataType::Uuid).may_be_unset(),
    ])
    .with_registry(HELPERS);
    case.loading_from_rows = loading_from_rows;
    case
}

/// A founder reads the grant naming them on their own organization's root and no other, and
/// a range is read where its bounds compare as the policies state and never where one is
/// NULL.
#[tokio::test]
#[ignore = "requires Docker, postgres:17, postgres:18, and openfga/openfga containers"]
async fn column_comparisons_agree_with_postgres_17_and_18() {
    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        for loading_from_rows in [false, true] {
            let case = compared_case(major, loading_from_rows);
            let run = support::parity::run_before(&cluster, &case, Duration::from_secs(180)).await;
            let expect = |subject: &str, object: &str, allowed| {
                assert_postgres(
                    &case,
                    &run,
                    subject,
                    object,
                    ActionStatement::Select,
                    allowed,
                );
            };
            expect(ALICE, &format!("grants:{ALICE_ORGANIZATION}|{ALICE}"), true);
            expect(BOB, &format!("grants:{BOB_ORGANIZATION}|{BOB}"), true);
            expect(BOB, &format!("grants:{ALICE_ORGANIZATION}|{BOB}"), false);
            expect(ALICE, &format!("grants:{BOB_ORGANIZATION}|{ALICE}"), false);
            expect(ALICE, &format!("grants:{NESTED_RESOURCE}|{ALICE}"), false);
            for (range, allowed) in [
                ("equal", true),
                ("ascending", true),
                ("descending", true),
                ("descending_same", false),
                ("null_low", false),
                ("null_high", false),
                ("null_label", false),
            ] {
                expect("anonymous", &format!("ranges:{range}"), allowed);
            }
            assert_agrees(&case, &run);
        }
    }
}
