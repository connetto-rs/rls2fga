#![cfg(not(target_os = "windows"))]

use rls2fga::generator::well_known::{
    WellKnownTypes, NOBODY_TYPE, PG_ROLE_TYPE, REQUEST_GATE_TYPE, TEAM_TYPE,
};
use rls2fga::translator::TranslatorBuilder;
use rls2fga::types::ConfidenceLevel;

use crate::support;
use crate::support::deployment::{deployment, scalar};

#[tokio::test]
#[ignore = "requires Docker and OpenFGA container"]
async fn openfga_accepts_generated_model_and_checks_pass() {
    // 1. Start OpenFGA container
    let container = support::containers::start_openfga().await;

    let grpc_port = container.get_host_port_ipv4(8081).await.unwrap();
    let mut service_client = support::openfga::connect(grpc_port).await;

    // 2. Create store
    let store_id = support::openfga::create_store(&mut service_client, "integration-test").await;

    // 3. Write authorization model
    let (classified, db, registry) = support::load_fixture_classified("earth_metabolome");
    let model =
        support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B).json_model();
    let model_id =
        support::openfga::write_authorization_model(&mut service_client, &store_id, &model).await;

    // 4. Create scoped client and write tuples
    let client = service_client.into_client(&store_id, &model_id);

    let mut tuples: Vec<_> = support::openfga::EARTH_METABOLOME_TUPLES
        .iter()
        .map(|(obj, rel, user)| support::openfga::make_tuple(obj, rel, user))
        .collect();
    tuples.extend(support::openfga::gate_tuples([
        "ownables:doc1",
        "ownables:doc2",
    ]));

    support::openfga::write_tuples(&client, tuples).await;

    // 5. Check assertions
    let checks = support::openfga::EARTH_METABOLOME_CHECKS;

    let mut failures = Vec::new();
    for (user, relation, object, expected) in &checks {
        let allowed = support::openfga::check_allowed(&client, user, relation, object).await;
        if allowed != *expected {
            failures.push(format!(
                "  {user} {relation} {object}: expected {expected}, got {allowed}"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "Authorization check failures:\n{}",
        failures.join("\n")
    );
}

#[tokio::test]
#[ignore = "requires Docker and OpenFGA container"]
async fn openfga_accepts_generated_condition_parameter_names() {
    let container = support::containers::start_openfga().await;
    let grpc_port = container.get_host_port_ipv4(8081).await.unwrap();
    let mut client = support::openfga::connect(grpc_port).await;
    let store_id = support::openfga::create_store(&mut client, "condition-parameter-test").await;

    let schema = r#"
CREATE TABLE tenant_docs(id UUID PRIMARY KEY, "tenant-id" TEXT);
CREATE TABLE timed_docs(id UUID PRIMARY KEY, "in" TIMESTAMPTZ);
ALTER TABLE tenant_docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE timed_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON tenant_docs FOR SELECT
    USING ("tenant-id" = current_setting('app.tenant'));
CREATE POLICY p ON timed_docs FOR SELECT USING ("in" > now());
"#;
    let well_known = WellKnownTypes::new(
        "Principal-Team/V2.member",
        TEAM_TYPE,
        PG_ROLE_TYPE,
        REQUEST_GATE_TYPE,
        NOBODY_TYPE,
    )
    .expect("the extended type name should be valid");
    let db = support::footgun::db_of(schema);
    let model = TranslatorBuilder::new(deployment([scalar("app.tenant")]))
        .with_request_time_parameter("as_of_2")
        .expect("as_of_2 is a valid parameter")
        .with_well_known_types(well_known)
        .build()
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .json_model();

    let conditions = model.conditions.as_ref().expect("conditions should exist");
    // The tenant travels in the `settings` map the check carries, which the tenant gate
    // reads under the value's parameter name.
    assert!(conditions
        .values()
        .any(|condition| condition.parameters.contains_key("settings")));
    assert!(conditions
        .values()
        .any(|condition| condition.parameters.contains_key("_in")));
    support::openfga::write_authorization_model(&mut client, &store_id, &model).await;
}
