// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use oan_identity_sidecar::{
    config::Config, headers::strip_untrusted_identity_headers, runtime_connector::*, verify_inbound,
};
use serde_json::{json, Value};

#[test]
fn runtime_context_accepts_response_signing_capability_but_rejects_unknown_fields() {
    let mut context = json!({"subjectDid":"caller", "audienceDid":"target", "requestId":"req", "payloadDigest":"sha256:body", "responseSigningSupported":true});
    assert!(
        serde_json::from_value::<VerifiedRuntimeContext>(context.clone())
            .unwrap()
            .response_signing_supported
    );
    context
        .as_object_mut()
        .unwrap()
        .remove("responseSigningSupported");
    assert!(
        !serde_json::from_value::<VerifiedRuntimeContext>(context.clone())
            .unwrap()
            .response_signing_supported
    );
    context["untrustedExtension"] = json!(true);
    assert!(serde_json::from_value::<VerifiedRuntimeContext>(context).is_err());
}

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
            callback_did: None,
            response_signing_supported: true,
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
fn unix_runtime_requires_explicit_owner_acl_binding() {
    let mut config: Config = serde_json::from_str(include_str!("../examples/config.json")).unwrap();
    config.runtime_endpoint = "unix:/tmp/oan-runtime.sock".into();
    config.runtime_owner_uid = None;
    assert!(config.validate().is_err());
    config.runtime_owner_uid = Some(0);
    assert!(config.validate().is_ok());
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
            callback_did: None,
            response_signing_supported: true,
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

struct IpcError;
impl RuntimeIpcTransport for IpcError {
    async fn round_trip(&self, _frame: Vec<u8>) -> Result<Vec<u8>, String> {
        Err("transport_unavailable".into())
    }
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

#[tokio::test]
async fn authenticated_ipc_rejects_context_substitution_even_with_matching_input_digest() {
    let envelope = json!({"signed":"message"});
    let digest = oan_identity_sidecar::runtime_connector::input_digest(
        &envelope,
        "did:oan:target",
        "request",
        "sha256:body",
    );
    let response = serde_json::to_vec(&json!({
        "version": IPC_VERSION, "callerId":"process-a", "tenantId":"tenant-a",
        "context":{"subjectDid":"did:oan:caller","audienceDid":"did:oan:other","requestId":"request","payloadDigest":"sha256:body","callerId":"process-a","tenantId":"tenant-a"},
        "inputDigest":digest
    })).unwrap();
    let connector = AuthenticatedRuntimeConnector::new(
        IpcEcho { response },
        "b".repeat(32),
        "process-a".into(),
        Some("tenant-a".into()),
    )
    .unwrap();
    assert_eq!(
        connector
            .verify_authenticated(&envelope, "did:oan:target", "request", "sha256:body")
            .await
            .unwrap_err(),
        "ipc_result_binding_mismatch"
    );
}

#[tokio::test]
async fn authenticated_ipc_rejects_invalid_bearer_and_transport_failure() {
    assert!(AuthenticatedRuntimeConnector::new(
        IpcError,
        "too-short".into(),
        "process-a".into(),
        None,
    )
    .is_err());
    let connector =
        AuthenticatedRuntimeConnector::new(IpcError, "b".repeat(32), "process-a".into(), None)
            .unwrap();
    assert_eq!(
        connector
            .verify_authenticated(&json!({}), "did:oan:target", "request", "sha256:body")
            .await
            .unwrap_err(),
        "transport_unavailable"
    );
}

#[tokio::test]
async fn authenticated_ipc_callback_binds_callback_did_and_canonical_digest() {
    let envelope = json!({"b": 2, "a": 1});
    let callback = "did:oan:K7mQ9:11111111111111111111111111111111";
    let callback_input_digest = oan_identity_sidecar::runtime_connector::input_digest_with_callback(
        &envelope,
        "did:oan:target",
        "request",
        "sha256:body",
        Some(callback),
    );
    let response = serde_json::to_vec(&json!({
        "version": IPC_VERSION,
        "callerId": "process-a",
        "tenantId": "tenant-a",
        "context": {"subjectDid":callback,"audienceDid":"did:oan:target","requestId":"request","payloadDigest":"sha256:body","callerId":"process-a","tenantId":"tenant-a","callbackDid":callback},
        "inputDigest": callback_input_digest
    })).unwrap();
    let connector = AuthenticatedRuntimeConnector::new(
        IpcEcho { response },
        "b".repeat(32),
        "process-a".into(),
        Some("tenant-a".into()),
    )
    .unwrap();
    let context = connector
        .verify_authenticated_callback(
            &envelope,
            "did:oan:target",
            "request",
            "sha256:body",
            callback,
        )
        .await
        .unwrap();
    assert_eq!(context.callback_did.as_deref(), Some(callback));
    let forged = serde_json::to_vec(&json!({
        "version": IPC_VERSION, "callerId": "process-a", "tenantId": "tenant-a",
        "context": {"subjectDid":callback,"audienceDid":"did:oan:target","requestId":"request","payloadDigest":"sha256:body","callerId":"other-process","tenantId":"tenant-a","callbackDid":callback},
        "inputDigest": callback_input_digest
    })).unwrap();
    let connector = AuthenticatedRuntimeConnector::new(
        IpcEcho { response: forged },
        "b".repeat(32),
        "process-a".into(),
        Some("tenant-a".into()),
    )
    .unwrap();
    assert_eq!(
        connector
            .verify_authenticated_callback(
                &envelope,
                "did:oan:target",
                "request",
                "sha256:body",
                callback
            )
            .await
            .unwrap_err(),
        "ipc_result_binding_mismatch"
    );
    assert_eq!(
        input_digest(
            &json!({"b":2,"a":1}),
            "did:oan:target",
            "request",
            "sha256:body"
        ),
        "sha256:48c7e132aa35a2dcc24fabefc72c9a3de47db5cb14e56547a4035a5be208dce4"
    );
}

#[tokio::test]
async fn authenticated_ipc_rejects_unknown_fields_wrong_version_and_oversized_frames() {
    let unknown = serde_json::to_vec(&json!({
        "version": IPC_VERSION,
        "callerId": "process-a",
        "tenantId": "tenant-a",
        "context": {"subjectDid":"did:oan:caller","audienceDid":"did:oan:target","requestId":"request","payloadDigest":"sha256:body","callerId":"process-a","tenantId":"tenant-a"},
        "inputDigest": "wrong",
        "extra": true
    })).unwrap();
    let connector = AuthenticatedRuntimeConnector::new(
        IpcEcho { response: unknown },
        "b".repeat(32),
        "process-a".into(),
        Some("tenant-a".into()),
    )
    .unwrap();
    assert_eq!(
        connector
            .verify_authenticated(&json!({}), "did:oan:target", "request", "sha256:body")
            .await
            .unwrap_err(),
        "ipc_schema_invalid"
    );

    let wrong_version = serde_json::to_vec(&json!({
        "version": "oan-runtime-ipc-v0",
        "callerId": "process-a",
        "tenantId": "tenant-a",
        "context": {"subjectDid":"did:oan:caller","audienceDid":"did:oan:target","requestId":"request","payloadDigest":"sha256:body","callerId":"process-a","tenantId":"tenant-a"},
        "inputDigest": "wrong"
    })).unwrap();
    let connector = AuthenticatedRuntimeConnector::new(
        IpcEcho {
            response: wrong_version,
        },
        "b".repeat(32),
        "process-a".into(),
        Some("tenant-a".into()),
    )
    .unwrap();
    assert_eq!(
        connector
            .verify_authenticated(&json!({}), "did:oan:target", "request", "sha256:body")
            .await
            .unwrap_err(),
        "ipc_result_binding_mismatch"
    );

    let oversized = IpcEcho {
        response: vec![b' '; 256 * 1024 + 1],
    };
    let connector =
        AuthenticatedRuntimeConnector::new(oversized, "b".repeat(32), "process-a".into(), None)
            .unwrap();
    assert_eq!(
        connector
            .verify_authenticated(&json!({}), "did:oan:target", "request", "sha256:body")
            .await
            .unwrap_err(),
        "ipc_frame_too_large"
    );
}

#[test]
fn response_signing_is_opt_in_and_round_trips_from_config() {
    let config: Config = serde_json::from_str(include_str!("../examples/config.json")).unwrap();
    assert!(!config.response_signing);

    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("../examples/config.json")).unwrap();
    value["responseSigning"] = serde_json::Value::Bool(true);
    let enabled: Config = serde_json::from_value(value).unwrap();
    assert!(enabled.response_signing);
    assert!(enabled.validate().is_ok());
}
