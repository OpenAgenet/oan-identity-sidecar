// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! Runtime-signed outbound HTTP boundary. The Sidecar never constructs an
//! identity signature itself; Runtime returns the signed envelope and the
//! Sidecar only binds it to the exact method, target and body bytes.

use crate::runtime_connector::{AuthenticatedRuntimeConnector, RuntimeIpcTransport};
use base64::Engine;
use reqwest::{Client, Method, Url};
use sha2::Digest;

pub struct OutboundRequest {
    pub method: Method,
    pub target: Url,
    pub body: Vec<u8>,
    pub request_id: String,
    pub audience_did: String,
    pub purpose: String,
}

pub async fn send_authenticated<T: RuntimeIpcTransport>(
    runtime: &AuthenticatedRuntimeConnector<T>,
    request: OutboundRequest,
) -> Result<reqwest::Response, String> {
    if request.target.username() != ""
        || request.target.password().is_some()
        || request.target.fragment().is_some()
    {
        return Err("outbound_target_invalid".into());
    }
    let payload_digest = format!("sha256:{:x}", sha2::Sha256::digest(&request.body));
    let intent = serde_json::json!({
        "method": request.method.as_str(), "target": request.target.as_str(),
        "requestId": request.request_id, "audienceDid": request.audience_did,
        "purpose": request.purpose, "payloadDigest": payload_digest
    });
    let signed = runtime.sign_authenticated(&intent).await?;
    let envelope = signed.get("envelope").ok_or("outbound_envelope_missing")?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(envelope).map_err(|_| "outbound_envelope_invalid")?);
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "outbound_client_init_failed")?;
    client
        .request(request.method, request.target)
        .header("x-oan-envelope", encoded)
        .header("x-oan-request-id", request.request_id)
        .body(request.body)
        .send()
        .await
        .map_err(|_| "outbound_unavailable".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_connector::RuntimeIpcTransport;
    use serde_json::json;

    struct Mock;
    impl RuntimeIpcTransport for Mock {
        async fn round_trip(&self, frame: Vec<u8>) -> Result<Vec<u8>, String> {
            let req: serde_json::Value = serde_json::from_slice(&frame).unwrap();
            let intent = req.get("intent").cloned().unwrap();
            let caller = req
                .get("expectedCallerId")
                .and_then(|v| v.as_str())
                .unwrap();
            let tenant = req.get("expectedTenantId").cloned().unwrap();
            Ok(serde_json::to_vec(&json!({"version":"oan-runtime-ipc-v1","callerId":caller,"tenantId":tenant,"signed":{"envelope":{"intent":intent}},"inputDigest":crate::runtime_connector::sign_input_digest(&intent,caller,tenant.as_str())})).unwrap())
        }
    }

    #[tokio::test]
    async fn outbound_intent_is_runtime_signed_and_bound() {
        let runtime = AuthenticatedRuntimeConnector::new(
            Mock,
            "x".repeat(32),
            "caller".into(),
            Some("tenant".into()),
        )
        .unwrap();
        let request = OutboundRequest {
            method: Method::POST,
            target: Url::parse("http://127.0.0.1:1/record").unwrap(),
            body: b"{}".to_vec(),
            request_id: "request".into(),
            audience_did: "did:oan:target".into(),
            purpose: "request".into(),
        };
        let result = send_authenticated(&runtime, request).await;
        assert!(matches!(result, Err(ref code) if code == "outbound_unavailable"));
    }
}
