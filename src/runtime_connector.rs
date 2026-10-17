// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! Protected connector contract. No unauthenticated network implementation is provided.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;

pub const IPC_VERSION: &str = "oan-runtime-ipc-v1";
const MAX_FRAME_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IpcVerifyRequest {
    pub version: String,
    pub operation: String,
    pub bearer: String,
    pub envelope: Value,
    pub expected_audience: String,
    pub expected_request_id: String,
    pub expected_payload_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IpcVerifiedContext {
    pub version: String,
    pub caller_id: String,
    pub tenant_id: Option<String>,
    pub context: VerifiedRuntimeContext,
    pub input_digest: String,
}

/// A host-supplied authenticated IPC transport. The transport must authenticate
/// the OS peer (Unix credentials/named-pipe ACL) before invoking this callback.
pub trait RuntimeIpcTransport: Send + Sync {
    fn round_trip(
        &self,
        frame: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, String>> + Send;
}

/// Versioned Runtime connector. It never accepts caller/tenant from the
/// business envelope; those values are returned by the authenticated Runtime.
pub struct AuthenticatedRuntimeConnector<T> {
    transport: T,
    bearer: String,
    caller_id: String,
    tenant_id: Option<String>,
}
impl<T: RuntimeIpcTransport> AuthenticatedRuntimeConnector<T> {
    pub fn new(
        transport: T,
        bearer: String,
        caller_id: String,
        tenant_id: Option<String>,
    ) -> Result<Self, String> {
        if bearer.len() < 32 || bearer.len() > 512 || caller_id.is_empty() || caller_id.len() > 256
        {
            return Err("invalid_ipc_credentials".into());
        }
        Ok(Self {
            transport,
            bearer,
            caller_id,
            tenant_id,
        })
    }
    pub async fn verify_authenticated(
        &self,
        envelope: &Value,
        expected_audience: &str,
        expected_request_id: &str,
        expected_payload_digest: &str,
    ) -> Result<VerifiedRuntimeContext, String> {
        let request = IpcVerifyRequest {
            version: IPC_VERSION.into(),
            operation: "verify_request".into(),
            bearer: self.bearer.clone(),
            envelope: envelope.clone(),
            expected_audience: expected_audience.into(),
            expected_request_id: expected_request_id.into(),
            expected_payload_digest: expected_payload_digest.into(),
        };
        let frame = serde_json::to_vec(&request).map_err(|_| "ipc_schema_invalid")?;
        if frame.len() > MAX_FRAME_BYTES {
            return Err("ipc_frame_too_large".into());
        }
        let raw = self.transport.round_trip(frame).await?;
        if raw.len() > MAX_FRAME_BYTES {
            return Err("ipc_frame_too_large".into());
        }
        let response: IpcVerifiedContext =
            serde_json::from_slice(&raw).map_err(|_| "ipc_schema_invalid")?;
        if response.version != IPC_VERSION
            || response.caller_id != self.caller_id
            || response.tenant_id != self.tenant_id
            || response.input_digest
                != input_digest(
                    envelope,
                    expected_audience,
                    expected_request_id,
                    expected_payload_digest,
                )
        {
            return Err("ipc_result_binding_mismatch".into());
        }
        if response.context.caller_id.as_deref() != Some(response.caller_id.as_str())
            || response.context.tenant_id != response.tenant_id
        {
            return Err("ipc_result_binding_mismatch".into());
        }
        Ok(response.context)
    }
    pub async fn verify_authenticated_with_owner(
        &self,
        envelope: &Value,
        expected_audience: &str,
        expected_request_id: &str,
        expected_payload_digest: &str,
    ) -> Result<(VerifiedRuntimeContext, String, Option<String>), String> {
        let request = IpcVerifyRequest {
            version: IPC_VERSION.into(),
            operation: "verify_request".into(),
            bearer: self.bearer.clone(),
            envelope: envelope.clone(),
            expected_audience: expected_audience.into(),
            expected_request_id: expected_request_id.into(),
            expected_payload_digest: expected_payload_digest.into(),
        };
        let frame = serde_json::to_vec(&request).map_err(|_| "ipc_schema_invalid")?;
        if frame.len() > MAX_FRAME_BYTES {
            return Err("ipc_frame_too_large".into());
        }
        let raw = self.transport.round_trip(frame).await?;
        if raw.len() > MAX_FRAME_BYTES {
            return Err("ipc_frame_too_large".into());
        }
        let response: IpcVerifiedContext =
            serde_json::from_slice(&raw).map_err(|_| "ipc_schema_invalid")?;
        if response.version != IPC_VERSION
            || response.caller_id != self.caller_id
            || response.tenant_id != self.tenant_id
            || response.input_digest
                != input_digest(
                    envelope,
                    expected_audience,
                    expected_request_id,
                    expected_payload_digest,
                )
        {
            return Err("ipc_result_binding_mismatch".into());
        }
        if response.context.caller_id.as_deref() != Some(response.caller_id.as_str())
            || response.context.tenant_id != response.tenant_id
        {
            return Err("ipc_result_binding_mismatch".into());
        }
        Ok((response.context, response.caller_id, response.tenant_id))
    }
}
impl<T: RuntimeIpcTransport> RuntimeVerifier for AuthenticatedRuntimeConnector<T> {
    async fn verify_request(
        &self,
        envelope: &Value,
        expected_audience: &str,
        expected_request_id: &str,
        expected_payload_digest: &str,
    ) -> Result<VerifiedRuntimeContext, String> {
        self.verify_authenticated(
            envelope,
            expected_audience,
            expected_request_id,
            expected_payload_digest,
        )
        .await
    }
}

pub fn input_digest(
    envelope: &Value,
    audience: &str,
    request_id: &str,
    payload_digest: &str,
) -> String {
    let bytes = serde_json::to_vec(&serde_json::json!({"envelope":envelope,"audience":audience,"requestId":request_id,"payloadDigest":payload_digest})).unwrap_or_default();
    format!("{:x}", sha2::Sha256::digest(bytes))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedRuntimeContext {
    pub subject_did: String,
    pub audience_did: String,
    pub request_id: String,
    pub payload_digest: String,
    #[serde(default)]
    pub caller_id: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
}

/// A trusted host implements this only after authenticating the Runtime channel.
/// The Runtime must verify evidence, session, audience, digest, time and replay.
pub trait RuntimeVerifier: Send + Sync {
    fn verify_request(
        &self,
        envelope: &Value,
        expected_audience: &str,
        expected_request_id: &str,
        expected_payload_digest: &str,
    ) -> impl std::future::Future<Output = Result<VerifiedRuntimeContext, String>> + Send;
}

/// Secure default until protected IPC and its versioned wire contract are implemented.
pub struct UnavailableRuntime;
impl RuntimeVerifier for UnavailableRuntime {
    async fn verify_request(
        &self,
        _: &Value,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<VerifiedRuntimeContext, String> {
        Err("runtime_connector_not_configured".into())
    }
}

/// Outbound signing is a separate host operation, not arbitrary byte signing.
/// The connector binds tenant/caller through the authenticated IPC channel.
pub trait RuntimeSigner: Send + Sync {
    fn sign_intent(
        &self,
        intent: &Value,
    ) -> impl std::future::Future<Output = Result<Value, String>> + Send;
}
