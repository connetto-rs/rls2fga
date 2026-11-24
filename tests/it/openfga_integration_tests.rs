#![cfg(not(target_os = "windows"))]

use rls2fga::generator::well_known::{
    WellKnownTypes, NOBODY_TYPE, PG_ROLE_TYPE, REQUEST_GATE_TYPE, TEAM_TYPE,
};
use rls2fga::translator::TranslatorBuilder;

use crate::support;
use crate::support::deployment::{deployment, scalar};

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
