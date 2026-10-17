// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use oan_identity_sidecar::{
    config::Config, headers::strip_untrusted_identity_headers, runtime_connector::*, verify_inbound,
};
use serde_json::{json, Value};

#[test]
fn removes_spoofed_headers_case_insensitively() {
    let headers = vec![
        ("X-OAN-DID".into(), "forged".into()),
        ("x-verified-principal".into(), "forged".into()),
        ("content-type".into(), "application/json".into()),
    ];
    assert_eq!(
        strip_untrusted_identity_headers(&headers),
        vec![("content-type".into(), "application/json".into())]
    );
}
#[tokio::test]
async fn unavailable_runtime_fails_closed() {
    assert!(verify_inbound(
        &UnavailableRuntime,
        &json!({}),
        "did:oan:target",
        "req",
        "sha256:body"
    )
    .await
    .is_err());
}
struct WrongAudience;
impl RuntimeVerifier for WrongAudience {
    async fn verify_request(
        &self,
        _: &Value,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<VerifiedRuntimeContext, String> {
        Ok(VerifiedRuntimeContext {
            subject_did: "did:oan:caller".into(),
            audience_did: "wrong".into(),
            request_id: "req".into(),
            payload_digest: "sha256:body".into(),
            caller_id: None,
            tenant_id: None,
        })
    }
}
#[tokio::test]
async fn rejects_misbound_runtime_result() {
    assert!(verify_inbound(
        &WrongAudience,
        &json!({}),
        "did:oan:target",
        "req",
        "sha256:body"
    )
    .await
    .is_err());
}
#[test]
fn only_local_backend_is_allowed() {
    let mut config: Config = serde_json::from_str(include_str!("../examples/config.json")).unwrap();
    assert!(config.validate().is_ok());
    config.backend_url = "http://evil.example".into();
    assert!(config.validate().is_err());
}

#[test]
fn malformed_dids_and_empty_ipc_names_are_rejected() {
    let mut config: Config = serde_json::from_str(include_str!("../examples/config.json")).unwrap();
    config.runtime_endpoint = "pipe:".into();
    assert!(config.validate().is_err());
    config.runtime_endpoint = "unix:/".into();
    assert!(config.validate().is_err());
    config.runtime_endpoint = "pipe:runtime".into();
    config.resource_did = "did:oan:invalid".into();
    assert!(config.validate().is_err());
}

struct VerifiedMock;
impl RuntimeVerifier for VerifiedMock {
    async fn verify_request(
        &self,
        _: &Value,
        audience: &str,
        request_id: &str,
        digest: &str,
    ) -> Result<VerifiedRuntimeContext, String> {
        Ok(VerifiedRuntimeContext {
            subject_did: "did:oan:K7mQ9:11111111111111111111111111111111".into(),
            audience_did: audience.into(),
            request_id: request_id.into(),
            payload_digest: digest.into(),
            caller_id: Some("process-a".into()),
            tenant_id: Some("tenant-a".into()),
        })
    }
}
#[tokio::test]
async fn authenticated_runtime_result_creates_principal() {
    let principal = verify_inbound(
        &VerifiedMock,
        &json!({}),
        "did:oan:K7mQ9:22222222222222222222222222222222",
        "req",
        "sha256:body",
    )
    .await
    .unwrap();
    assert_eq!(
        principal.subject_did(),
        "did:oan:K7mQ9:11111111111111111111111111111111"
    );
    assert_eq!(principal.request_id(), "req");
}

struct IpcEcho {
    response: Vec<u8>,
}
impl RuntimeIpcTransport for IpcEcho {
    async fn round_trip(&self, _frame: Vec<u8>) -> Result<Vec<u8>, String> {
        let response = self.response.clone();
        Ok(response)
    }
}

#[tokio::test]
async fn authenticated_ipc_binds_version_caller_tenant_and_input() {
    let envelope = json!({"signed":"message"});
    let input_digest = oan_identity_sidecar::runtime_connector::input_digest(
        &envelope,
        "did:oan:target",
        "request",
        "sha256:body",
    );
    let response = serde_json::to_vec(&json!({
        "version": IPC_VERSION,
        "callerId": "process-a",
        "tenantId": "tenant-a",
        "context": {"subjectDid":"did:oan:caller","audienceDid":"did:oan:target","requestId":"request","payloadDigest":"sha256:body","callerId":"process-a","tenantId":"tenant-a"},
        "inputDigest": input_digest
    })).unwrap();
    let connector = AuthenticatedRuntimeConnector::new(
        IpcEcho { response },
        "b".repeat(32),
        "process-a".into(),
        Some("tenant-a".into()),
    )
    .unwrap();
    let context = connector
        .verify_authenticated(&envelope, "did:oan:target", "request", "sha256:body")
        .await
        .unwrap();
    assert_eq!(context.subject_did, "did:oan:caller");
}

#[tokio::test]
async fn authenticated_ipc_context_becomes_read_only_verified_principal() {
    let envelope = json!({"signed":"message"});
    let input_digest = oan_identity_sidecar::runtime_connector::input_digest(
        &envelope,
        "did:oan:target",
        "request",
        "sha256:body",
    );
    let response = serde_json::to_vec(&json!({
        "version": IPC_VERSION,
        "callerId": "process-a",
        "tenantId": "tenant-a",
        "context": {"subjectDid":"did:oan:K7mQ9:11111111111111111111111111111111","audienceDid":"did:oan:target","requestId":"request","payloadDigest":"sha256:body","callerId":"process-a","tenantId":"tenant-a"},
        "inputDigest": input_digest
    })).unwrap();
    let connector = AuthenticatedRuntimeConnector::new(
        IpcEcho { response },
        "b".repeat(32),
        "process-a".into(),
        Some("tenant-a".into()),
    )
    .unwrap();
    let principal = verify_inbound(
        &connector,
        &envelope,
        "did:oan:target",
        "request",
        "sha256:body",
    )
    .await
    .unwrap();
    assert_eq!(principal.caller_id(), Some("process-a"));
    assert_eq!(principal.tenant_id(), Some("tenant-a"));
}

#[tokio::test]
async fn authenticated_ipc_rejects_forged_caller_or_result_binding() {
    let response = serde_json::to_vec(&json!({
        "version": IPC_VERSION,
        "callerId": "attacker",
        "tenantId": "tenant-a",
        "context": {"subjectDid":"did:oan:caller","audienceDid":"did:oan:target","requestId":"request","payloadDigest":"sha256:body","callerId":"process-a","tenantId":"tenant-a"},
        "inputDigest": "wrong"
    })).unwrap();
    let connector = AuthenticatedRuntimeConnector::new(
        IpcEcho { response },
        "b".repeat(32),
        "process-a".into(),
        Some("tenant-a".into()),
    )
    .unwrap();
    assert!(connector
        .verify_authenticated(&json!({}), "did:oan:target", "request", "sha256:body")
        .await
        .is_err());
}
