// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

pub mod config;
pub mod headers;
pub mod runtime_connector;

use runtime_connector::RuntimeVerifier;
use serde_json::{json, Value};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BoundaryError {
    #[error("invalid_config")]
    InvalidConfig,
    #[error("runtime_verification_failed")]
    VerificationFailed,
    #[error("verified_context_binding_mismatch")]
    BindingMismatch,
}

/// Constructible only through the verified boundary, never directly from headers.
#[derive(Clone, Debug)]
pub struct VerifiedPrincipal {
    subject_did: String,
    request_id: String,
    caller_id: Option<String>,
    tenant_id: Option<String>,
}
impl VerifiedPrincipal {
    pub fn subject_did(&self) -> &str {
        &self.subject_did
    }
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    pub fn caller_id(&self) -> Option<&str> {
        self.caller_id.as_deref()
    }
    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }
}

pub async fn verify_inbound(
    runtime: &impl RuntimeVerifier,
    envelope: &Value,
    audience: &str,
    request_id: &str,
    payload_digest: &str,
) -> Result<VerifiedPrincipal, BoundaryError> {
    let context = runtime
        .verify_request(envelope, audience, request_id, payload_digest)
        .await
        .map_err(|_| BoundaryError::VerificationFailed)?;
    if context.audience_did != audience
        || context.request_id != request_id
        || context.payload_digest != payload_digest
        || oan_did_oan::DidOan::parse(&context.subject_did).is_err()
    {
        return Err(BoundaryError::BindingMismatch);
    }
    Ok(VerifiedPrincipal {
        subject_did: context.subject_did,
        request_id: context.request_id,
        caller_id: context.caller_id,
        tenant_id: context.tenant_id,
    })
}

pub async fn verify_inbound_authenticated<T: runtime_connector::RuntimeIpcTransport>(
    runtime: &runtime_connector::AuthenticatedRuntimeConnector<T>,
    envelope: &Value,
    audience: &str,
    request_id: &str,
    payload_digest: &str,
) -> Result<VerifiedPrincipal, BoundaryError> {
    let (context, caller_id, tenant_id) = runtime
        .verify_authenticated_with_owner(envelope, audience, request_id, payload_digest)
        .await
        .map_err(|_| BoundaryError::VerificationFailed)?;
    if context.audience_did != audience
        || context.request_id != request_id
        || context.payload_digest != payload_digest
        || oan_did_oan::DidOan::parse(&context.subject_did).is_err()
    {
        return Err(BoundaryError::BindingMismatch);
    }
    Ok(VerifiedPrincipal {
        subject_did: context.subject_did,
        request_id: context.request_id,
        caller_id: Some(caller_id),
        tenant_id,
    })
}

pub fn capabilities() -> Value {
    json!({"stage":"ipc-contract", "networkServer":false, "runtimeConnector":false, "mutualAuthentication":false})
}
