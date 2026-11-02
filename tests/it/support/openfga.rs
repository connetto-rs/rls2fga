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

pub(crate) async fn check_allowed(
    client: &OpenFgaClient<Channel>,
    user: &str,
    relation: &str,
    object: &str,
) -> bool {
    client
        .check_simple(TupleKeyWithoutCondition {
            user: user.to_string(),
            relation: relation.to_string(),
            object: object.to_string(),
        })
        .await
        .expect("check request should succeed")
}

pub(crate) fn make_tuple(object: &str, relation: &str, user: &str) -> TupleKey {
    TupleKey {
        user: user.to_string(),
        relation: relation.to_string(),
        object: object.to_string(),
        condition: None,
    }
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
/// come from.
pub(crate) async fn check_allowed_with_context(
    client: &OpenFgaClient<Channel>,
    user: &str,
    relation: &str,
    object: &str,
    context: serde_json::Value,
) -> bool {
    client
        .check(
            TupleKeyWithoutCondition {
                user: user.to_string(),
                relation: relation.to_string(),
                object: object.to_string(),
            },
            None,
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
