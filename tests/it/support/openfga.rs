use std::collections::BTreeSet;

use openfga_client::client::{
    AuthorizationModel, CreateStoreRequest, OpenFgaClient, OpenFgaServiceClient,
    ReadAuthorizationModelRequest, TupleKey, TupleKeyWithoutCondition,
};
use openfga_client::tonic::transport::Channel;

pub(crate) type GrpcClient = OpenFgaServiceClient<Channel>;

/// The store-scoped client every check goes through.
pub(crate) type Client = OpenFgaClient<Channel>;

pub(crate) async fn connect(grpc_port: u16) -> GrpcClient {
    OpenFgaServiceClient::connect(format!("http://localhost:{grpc_port}"))
        .await
        .expect("gRPC connection to OpenFGA should succeed")
}

pub(crate) async fn create_store(client: &mut GrpcClient, name: &str) -> String {
    let response = client
        .create_store(CreateStoreRequest {
            name: name.to_string(),
        })
        .await
        .expect("store creation should succeed");

    response.into_inner().id
}

pub(crate) async fn write_authorization_model(
    client: &mut GrpcClient,
    store_id: &str,
    model: &rls2fga::generator::json_model::AuthorizationModel,
) -> String {
    rls2fga::client::write_authorization_model(client, store_id, model)
        .await
        .expect("authorization model write should succeed")
}

/// Tuples `OpenFGA` accepts in one write by default.
const MAX_TUPLES_PER_WRITE: usize = 100;

pub(crate) async fn write_tuples(client: &OpenFgaClient<Channel>, mut tuples: Vec<TupleKey>) {
    while !tuples.is_empty() {
        let rest = tuples.split_off(tuples.len().min(MAX_TUPLES_PER_WRITE));
        client
            .write(tuples, None)
            .await
            .expect("tuple write should succeed");
        tuples = rest;
    }
}

/// Check as a request acting as the suite's acting role.
pub(crate) async fn check_allowed(
    client: &OpenFgaClient<Channel>,
    user: &str,
    relation: &str,
    object: &str,
) -> bool {
    check_allowed_with_context(client, user, relation, object, serde_json::json!({})).await
}

/// The contextual tuple stating that `user` acts as the role `kind`, which every check
/// carries.
pub(crate) fn acting_kind(user: &str, kind: &str) -> TupleKey {
    make_tuple(&format!("pg_role:{kind}"), "usage", user)
}

pub(crate) fn make_tuple(object: &str, relation: &str, user: &str) -> TupleKey {
    TupleKey {
        user: user.to_string(),
        relation: relation.to_string(),
        object: object.to_string(),
        condition: None,
    }
}

/// The structural tuples a set of hand-built facts on guarded rows needs, one link
/// from each row to its type's gate object and one constant per type admitting the
/// suite's acting role on that gate, which the tuple SQL would write for the rows it
/// stands in for.
pub(crate) fn gate_tuples<'a>(objects: impl IntoIterator<Item = &'a str>) -> Vec<TupleKey> {
    let objects: BTreeSet<&str> = objects.into_iter().collect();
    let role = super::deployment::ACTING_ROLE;
    let mut tuples = Vec::new();
    for object in &objects {
        let (type_name, _) = object
            .split_once(':')
            .expect("a guarded object names its type");
        tuples.push(make_tuple(
            object,
            rls2fga::generator::well_known::request_gate_link_relation().as_str(),
            &format!(
                "{}:{type_name}",
                rls2fga::generator::well_known::REQUEST_GATE_TYPE
            ),
        ));
    }
    let types: BTreeSet<&str> = objects
        .iter()
        .map(|object| {
            object
                .split_once(':')
                .expect("a guarded object names its type")
                .0
        })
        .collect();
    for type_name in types {
        tuples.push(make_tuple(
            &format!(
                "{}:{type_name}",
                rls2fga::generator::well_known::REQUEST_GATE_TYPE
            ),
            &format!("acting_{role}"),
            &format!(
                "{}:{role}#usage",
                rls2fga::generator::well_known::PG_ROLE_TYPE
            ),
        ));
    }
    tuples
}

/// A tuple carrying the condition its relation reference names, plus the context the
/// row supplies. The request supplies the rest at check time.
pub(crate) fn make_conditional_tuple(
    object: &str,
    relation: &str,
    user: &str,
    condition: &str,
    context: serde_json::Value,
) -> TupleKey {
    TupleKey {
        user: user.to_string(),
        relation: relation.to_string(),
        object: object.to_string(),
        condition: Some(openfga_client::client::RelationshipCondition {
            name: condition.to_string(),
            context: Some(to_struct(context)),
        }),
    }
}

/// Check with a request context, which is where a condition's remaining parameters
/// come from, as a request acting as the suite's acting role.
pub(crate) async fn check_allowed_with_context(
    client: &OpenFgaClient<Channel>,
    user: &str,
    relation: &str,
    object: &str,
    context: serde_json::Value,
) -> bool {
    check_as(
        client,
        super::deployment::ACTING_ROLE,
        user,
        relation,
        object,
        context,
    )
    .await
}

/// Check with a request context as a request acting as the role `kind`. Only a subject of
/// the caller type states a kind, since `pg_role#usage` admits no other.
pub(crate) async fn check_as(
    client: &OpenFgaClient<Channel>,
    kind: &str,
    user: &str,
    relation: &str,
    object: &str,
    context: serde_json::Value,
) -> bool {
    let is_caller = user
        .split_once(':')
        .is_some_and(|(type_name, _)| type_name == rls2fga::generator::well_known::USER_TYPE);
    client
        .check(
            TupleKeyWithoutCondition {
                user: user.to_string(),
                relation: relation.to_string(),
                object: object.to_string(),
            },
            if is_caller {
                vec![acting_kind(user, kind)]
            } else {
                Vec::new()
            },
            to_struct(context),
            false,
        )
        .await
        .expect("check request should succeed")
}

fn to_struct(value: serde_json::Value) -> openfga_client::prost_wkt_types::Struct {
    serde_json::from_value(value).expect("a JSON object converts to a protobuf struct")
}

pub(crate) async fn read_authorization_model(
    client: &mut GrpcClient,
    store_id: &str,
    model_id: &str,
) -> AuthorizationModel {
    let response = client
        .read_authorization_model(ReadAuthorizationModelRequest {
            store_id: store_id.to_string(),
            id: model_id.to_string(),
        })
        .await
        .expect("read authorization model should succeed");

    response
        .into_inner()
        .authorization_model
        .expect("authorization model should be present")
}

pub(crate) const EARTH_METABOLOME_TUPLES: [(&str, &str, &str); 9] = [
    ("ownables:doc1", "owner_id", "owner_grants_owner:alice"),
    ("owner_grants_owner:alice", "owner_user", "user:alice"),
    ("ownables:doc2", "owner_id", "owner_grants_owner:alpha"),
    (
        "owner_grants_owner:alpha",
        "owner_team",
        "team_members_team:alpha",
    ),
    ("team_members_team:alpha", "member", "user:bob"),
    ("owner_grants_owner:alice", "grant_editor", "user:carol"),
    (
        "owner_grants_owner:alice",
        "grant_viewer",
        "team_members_team:beta",
    ),
    ("team_members_team:beta", "member", "user:dave"),
    ("owner_grants_owner:alpha", "grant_admin", "user:eve"),
];

pub(crate) const EARTH_METABOLOME_CHECKS: [(&str, &str, &str, bool); 20] = [
    // Direct ownership: alice owns doc1 -> admin -> editor -> viewer
    ("user:alice", "can_select", "ownables:doc1", true),
    ("user:alice", "can_insert", "ownables:doc1", true),
    ("user:alice", "can_update", "ownables:doc1", true),
    ("user:alice", "can_delete", "ownables:doc1", true),
    // Team ownership: bob via team:alpha owns doc2
    ("user:bob", "can_select", "ownables:doc2", true),
    ("user:bob", "can_insert", "ownables:doc2", true),
    ("user:bob", "can_update", "ownables:doc2", true),
    ("user:bob", "can_delete", "ownables:doc2", true),
    // Cross-resource isolation: bob has no relation to doc1
    ("user:bob", "can_select", "ownables:doc1", false),
    // Grant escalation: carol has grant_editor on doc1 -> editor -> viewer
    ("user:carol", "can_select", "ownables:doc1", true),
    ("user:carol", "can_insert", "ownables:doc1", true),
    ("user:carol", "can_update", "ownables:doc1", true),
    ("user:carol", "can_delete", "ownables:doc1", false), // editor != admin
    // Team-mediated grant: dave via team:beta grant_viewer on doc1
    ("user:dave", "can_select", "ownables:doc1", true),
    ("user:dave", "can_insert", "ownables:doc1", false), // viewer != editor
    ("user:dave", "can_update", "ownables:doc1", false), // viewer != editor
    // Admin grant: eve has grant_admin on doc2 -> admin -> editor -> viewer
    ("user:eve", "can_select", "ownables:doc2", true),
    ("user:eve", "can_delete", "ownables:doc2", true),
    // Cross-resource isolation
    ("user:eve", "can_select", "ownables:doc1", false),
    ("user:alice", "can_select", "ownables:doc2", false),
];
