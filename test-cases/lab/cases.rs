// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
mod fixtures;
use fixtures::*;
use oan_identity_sidecar::{
    capabilities,
    config::Config,
    headers::strip_untrusted_identity_headers,
    runtime_connector::{RuntimeVerifier, UnavailableRuntime, VerifiedRuntimeContext},
    verify_inbound,
};
use serde_json::{json, Value};

#[test]
fn sc_01_all_five_registered_dids_map_to_their_real_loopback_backend() {
    let manifest = manifest();
    for name in resource_names() {
        let actor = &manifest["resources"][name];
        let doc = document(actor);
        assert_eq!(doc["id"], actor["did"]);
        assert_eq!(doc["controller"], actor["controllerDid"]);
        let endpoint = actor["registeredAccess"]["url"].as_str().unwrap();
        assert!(doc["service"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["serviceEndpoint"] == endpoint));
        let config = Config {
            resource_did: actor["did"].as_str().unwrap().into(),
            backend_url: endpoint.into(),
            runtime_endpoint: "unix:/tmp/oan-lab-runtime.sock".into(),
            ingress_bind: None,
            backend_auth_token: None,
            runtime_bearer: None,
            caller_id: None,
            tenant_id: None,
            runtime_owner_uid: Some(0),
            runtime_owner_pid: None,
            response_signing: false,
        };
        config.validate().unwrap();
        let mut bad = config.clone();
        bad.resource_did = "did:oan:bad".into();
        assert!(bad.validate().is_err());
        bad = config.clone();
        bad.backend_url = "http://remote.example/".into();
        assert!(bad.validate().is_err());
        bad = config;
        bad.runtime_endpoint = "http://127.0.0.1:9999".into();
        assert!(bad.validate().is_err());
    }
}
#[test]
fn sc_02_strip_spoofed_principals_preserve_protocol_and_oauth_headers() {
    let headers = vec![
        ("X-OaN-Did".into(), "forged".into()),
        ("Forwarded".into(), "forged".into()),
        ("x-forwarded-for".into(), "forged".into()),
        ("x-verified-principal".into(), "forged".into()),
        ("MCP-Protocol-Version".into(), "negotiated".into()),
        ("Authorization".into(), "Bearer lab-placeholder".into()),
        ("Content-Type".into(), "application/json".into()),
    ];
    assert_eq!(
        strip_untrusted_identity_headers(&headers),
        headers[4..].to_vec()
    );
}
// Deliberate test double: checks Sidecar's binding gate only, NOT cryptographic verification/IPC.
struct ContextDouble {
    subject: String,
    fault: &'static str,
}
impl RuntimeVerifier for ContextDouble {
    async fn verify_request(
        &self,
        _: &Value,
        audience: &str,
        request: &str,
        digest: &str,
    ) -> Result<VerifiedRuntimeContext, String> {
        Ok(VerifiedRuntimeContext {
            subject_did: if self.fault == "subject" {
                "invalid".into()
            } else {
                self.subject.clone()
            },
            audience_did: if self.fault == "audience" {
                "wrong".into()
            } else {
                audience.into()
            },
            request_id: if self.fault == "request" {
                "wrong".into()
            } else {
                request.into()
            },
            payload_digest: if self.fault == "digest" {
                "wrong".into()
            } else {
                digest.into()
            },
            caller_id: Some("lab-process".into()),
            tenant_id: Some("lab-tenant".into()),
            callback_did: None,
        })
    }
}
#[tokio::test]
async fn sc_03_binding_gate_rejects_misbound_context_before_handler() {
    let m = manifest();
    let caller = m["resources"]["a2a-a"]["did"].as_str().unwrap();
    for name in resource_names() {
        let target = m["resources"][name]["did"].as_str().unwrap();
        for fault in ["audience", "request", "digest", "subject"] {
            let runtime = ContextDouble {
                subject: caller.into(),
                fault,
            };
            let mut executions = 0;
            if verify_inbound(&runtime, &json!({}), target, "request", "sha256:test-only")
                .await
                .is_ok()
            {
                executions += 1;
            }
            assert_eq!(executions, 0, "{name}: {fault}");
        }
        let principal = verify_inbound(
            &ContextDouble {
                subject: caller.into(),
                fault: "none",
            },
            &json!({}),
            target,
            "request",
            "sha256:test-only",
        )
        .await
        .unwrap();
        assert_eq!(principal.subject_did(), caller);
        assert_eq!(principal.request_id(), "request");
    }
}
#[tokio::test]
async fn sc_04_missing_real_runtime_never_authorizes_lab_resource() {
    let m = manifest();
    for name in resource_names() {
        assert!(verify_inbound(
            &UnavailableRuntime,
            &json!({"claimedVerified":true}),
            m["resources"][name]["did"].as_str().unwrap(),
            "request",
            "sha256:test-only"
        )
        .await
        .is_err());
    }
    assert_eq!(capabilities()["networkServer"], true);
    assert_eq!(capabilities()["runtimeConnector"], true);
    assert_eq!(capabilities()["callbackBinding"], true);
}
#[test]
#[ignore = "BLOCKED: real authenticated Runtime IPC and Sidecar network server required"]
fn sc_05_real_a2a_mcp_hermes_l2_and_backend_bypass() {
    panic!("not implemented; binding doubles do not satisfy L2");
}
#[test]
#[ignore = "BLOCKED: real proxy stream/cancellation/response verification required"]
fn sc_06_stream_order_and_disconnect_cleanup() {
    panic!("not implemented");
}
