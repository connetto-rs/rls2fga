//! Put a generated model on a running `OpenFGA` server.
//!
//! The only thing here a consumer could not write for itself is the guarantee:
//! that [`crate::generator::json_model::AuthorizationModel`]
//! serializes into what the write call accepts. It is kept here so a rename in
//! the emitted model breaks this crate's own tests rather than a consumer's.
//!
//! Writing tuples is deliberately absent. A tuple is a
//! [`Record`](crate::types::Record), which
//! [`records_from_row`](crate::types::records_from_row) and
//! [`record_from_tuple_row`](crate::translator::Outputs::record_from_tuple_row)
//! already produce, and batching, deletion and retry are the caller's policy.

use openfga_client::client::{
    AuthorizationModel as ProtoModel, OpenFgaServiceClient, WriteAuthorizationModelRequest,
};
use openfga_client::tonic::body::Body;
use openfga_client::tonic::client::GrpcService;
use openfga_client::tonic::codegen::{Body as ResponseBody, Bytes, StdError};
use openfga_client::tonic::Status;
use prost::Message;

use crate::generator::json_model::AuthorizationModel;

/// Why a model did not reach the server.
///
/// `#[non_exhaustive]`: a later failure costs a caller no rewrite.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WriteModelError {
    /// The model did not translate into the client's own types, which is this
    /// crate's fault rather than the caller's.
    #[error("the model does not translate into a write request: {0}")]
    Untranslatable(#[source] serde_json::Error),
    /// The server refused the write.
    #[error("the server refused the model: {0}")]
    Refused(#[source] Status),
}

/// Write `model` to `store_id` and return the id it was stored under.
///
/// Takes the client the caller built, so TLS, authentication and interceptors
/// stay on their own dependency, which is where a transport belongs.
///
/// # Errors
///
/// [`WriteModelError::Refused`] carries what the server said, and
/// [`WriteModelError::Untranslatable`] means the emitted model and the client's
/// types disagree, which nothing on the calling side can fix.
pub async fn write_authorization_model<T>(
    client: &mut OpenFgaServiceClient<T>,
    store_id: &str,
    model: &AuthorizationModel,
) -> Result<String, WriteModelError>
where
    T: GrpcService<Body>,
    T::Error: Into<StdError>,
    T::ResponseBody: ResponseBody<Data = Bytes> + Send + 'static,
    <T::ResponseBody as ResponseBody>::Error: Into<StdError> + Send,
{
    let proto = proto_model(model)?;

    // Spelled field by field rather than deserialized straight into the request, so
    // a field the request grows is a compile error here instead of a silent omission.
    let response = client
        .write_authorization_model(WriteAuthorizationModelRequest {
            store_id: store_id.to_string(),
            type_definitions: proto.type_definitions,
            schema_version: proto.schema_version,
            conditions: proto.conditions,
        })
        .await
        .map_err(WriteModelError::Refused)?;

    Ok(response.into_inner().authorization_model_id)
}

/// The size `OpenFGA` compares with its `maxAuthorizationModelSizeInBytes` setting
/// (256 KiB by default in `openfga/openfga` `pkg/server/config/config.go`) before it
/// stores `model`.
///
/// The server measures the protobuf encoding of the model it is about to store, which
/// carries the 26-character id it assigns, so the same id length is counted here.
///
/// # Errors
///
/// [`WriteModelError::Untranslatable`] when the emitted model and the client's types
/// disagree, exactly as [`write_authorization_model`] would report.
pub fn model_size_in_bytes(model: &AuthorizationModel) -> Result<usize, WriteModelError> {
    let mut proto = proto_model(model)?;
    proto.id = "0".repeat(STORED_MODEL_ID_LEN);
    Ok(proto.encoded_len())
}

/// Length of the ULID the server assigns a stored model.
const STORED_MODEL_ID_LEN: usize = 26;

fn proto_model(model: &AuthorizationModel) -> Result<ProtoModel, WriteModelError> {
    let value = serde_json::to_value(model).map_err(WriteModelError::Untranslatable)?;
    serde_json::from_value(value).map_err(WriteModelError::Untranslatable)
}
