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
