//! Writing a generated model to a running `OpenFGA` server.
//!
//! The claim under test is the one a consumer cannot check for itself: that the
//! emitted [`AuthorizationModel`] is what the write call accepts, and that the
//! model the server then holds is the one that was sent.

#![cfg(not(target_os = "windows"))]

use rls2fga::translator::TranslatorBuilder;
use rls2fga::types::ConfidenceLevel;

use crate::support;

const OWNERSHIP: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = auth_current_user_id());
";

const ACCESSOR_REGISTRY: &str =
    r#"{"auth_current_user_id": {"kind": "current_user_accessor", "returns": "text"}}"#;

#[tokio::test]
#[ignore = "requires Docker and an openfga/openfga container"]
async fn a_written_model_is_the_model_the_server_answers_from() {
    let container = support::containers::start_openfga().await;
    let grpc_port = container.get_host_port_ipv4(8081).await.unwrap();
    let mut service = support::openfga::connect(grpc_port).await;
    let store_id = support::openfga::create_store(&mut service, "client-surface").await;

    let db = support::deployment::db(OWNERSHIP);
    let model = TranslatorBuilder::new(support::deployment::caller_deployment())
        .with_min_confidence(ConfidenceLevel::B)
        .with_registry_json(ACCESSOR_REGISTRY)
        .expect("the registry parses")
        .build()
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .json_model();

    let model_id = rls2fga::client::write_authorization_model(&mut service, &store_id, &model)
        .await
        .expect("the server accepts the emitted model");
    assert!(
        !model_id.is_empty(),
        "the write answers with the model's id"
    );

    // The server hands back what it stored, so this compares the emitted model
    // against the one the checks below are answered from.
    let stored =
        support::openfga::read_authorization_model(&mut service, &store_id, &model_id).await;
    let mut stored = serde_json::to_value(&stored).expect("the stored model serializes");
    let stored = stored
        .as_object_mut()
        .expect("a model is an object")
        .remove("type_definitions")
        .expect("a stored model carries its types");
    let sent = serde_json::to_value(&model).expect("the emitted model serializes");
    assert_eq!(
        Some(&stored),
        sent.get("type_definitions"),
        "the server stored something other than what was sent"
    );
    assert!(
        stored.as_array().is_some_and(|types| types.len() >= 2),
        "the comparison is worth making only while the model has types: {stored}"
    );

    let client = service.into_client(&store_id, &model_id);
    let mut tuples = vec![support::openfga::make_tuple(
        "docs:d1",
        "owner",
        "user:alice",
    )];
    tuples.extend(support::openfga::gate_tuples(["docs:d1"]));
    support::openfga::write_tuples(&client, tuples).await;

    assert!(
        support::openfga::check_allowed(&client, "user:alice", "can_select", "docs:d1").await,
        "the owner reads the row"
    );
    assert!(
        !support::openfga::check_allowed(&client, "user:bob", "can_select", "docs:d1").await,
        "a stranger does not"
    );
}

/// The service itself refuses to grant the denial, whatever an operator writes.
///
/// Probed before the model changed: with `no_access: [user]` the write
/// `docs:d1#no_access@user:alice` is **accepted** and `can_insert` then answers allowed, so
/// the denial was a convention. Pointed at a type nobody is, the write is refused at the
/// point of the mistake and the check still answers no.
#[tokio::test]
#[ignore = "requires Docker and an openfga/openfga container"]
async fn the_denial_cannot_be_lifted_by_writing_a_fact() {
    let container = support::containers::start_openfga().await;
    let grpc_port = container.get_host_port_ipv4(8081).await.unwrap();

    let db = support::deployment::db(OWNERSHIP);
    let outputs = TranslatorBuilder::new(support::deployment::caller_deployment())
        .with_min_confidence(ConfidenceLevel::B)
        .with_registry_json(ACCESSOR_REGISTRY)
        .expect("the registry parses")
        .build()
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    let mut service = support::openfga::connect(grpc_port).await;
    let store = support::openfga::create_store(&mut service, "denial-cannot-be-lifted").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service, &store, &outputs.json_model())
            .await;
    let client = service.into_client(&store, &model_id);

    let forged = client
        .write(
            vec![support::openfga::make_tuple(
                "docs:d1",
                rls2fga::generator::well_known::deny_relation().as_str(),
                "user:alice",
            )],
            None,
        )
        .await;
    assert!(
        forged.is_err(),
        "the service must refuse a fact naming a person on the denial"
    );
    assert!(
        !support::openfga::check_allowed(&client, "user:alice", "can_insert", "docs:d1").await,
        "INSERT has no policy, so nobody may insert"
    );
}

/// The size and the type count the outputs report are the ones the server compares with
/// `maxAuthorizationModelSizeInBytes` and `maxTypesPerAuthorizationModel`, so a server
/// capped exactly there stores the model and one capped one lower refuses it.
#[tokio::test]
#[ignore = "requires Docker and an openfga/openfga container"]
async fn the_reported_size_and_type_count_are_what_the_server_measures() {
    const SIZE: &str = "OPENFGA_MAX_AUTHORIZATION_MODEL_SIZE_IN_BYTES";
    const TYPES: &str = "OPENFGA_MAX_TYPES_PER_AUTHORIZATION_MODEL";

    let db = support::deployment::db(OWNERSHIP);
    let outputs = TranslatorBuilder::new(support::deployment::caller_deployment())
        .with_min_confidence(ConfidenceLevel::B)
        .with_registry_json(ACCESSOR_REGISTRY)
        .expect("the registry parses")
        .build()
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let size = outputs
        .model_size_in_bytes()
        .expect("the model translates into the client's types");
    let types = outputs.type_count();

    for (setting, cap, refusal) in [
        (SIZE, size, None),
        (SIZE, size - 1, Some("model exceeds size limit")),
        (TYPES, types, None),
        (
            TYPES,
            types - 1,
            Some("The number of type definitions in an authorization model exceeds"),
        ),
    ] {
        let container =
            support::containers::start_openfga_with(&[(setting, cap.to_string())]).await;
        let grpc_port = container.get_host_port_ipv4(8081).await.unwrap();
        let mut service = support::openfga::connect(grpc_port).await;
        let store_id = support::openfga::create_store(&mut service, "model-limits").await;
        let written = rls2fga::client::write_authorization_model(
            &mut service,
            &store_id,
            &outputs.json_model(),
        )
        .await;
        let as_expected = match (&written, refusal) {
            (Ok(_), None) => true,
            (Err(rls2fga::client::WriteModelError::Refused(status)), Some(refusal)) => {
                status.message().starts_with(refusal)
            }
            _ => false,
        };
        assert!(
            as_expected,
            "{size} bytes and {types} types under {setting}={cap}: {written:?}"
        );
    }
}
