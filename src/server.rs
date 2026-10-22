// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! Minimal protected HTTP ingress. It deliberately implements only the proxy
//! boundary; protocol parsing and cryptographic verification stay in Runtime.

use crate::{
    config::Config,
    headers::strip_untrusted_identity_headers,
    runtime_connector::{local_runtime_transport, AuthenticatedRuntimeConnector},
};
use base64::Engine;
use futures_util::StreamExt;
use serde_json::Value;
use sha2::Digest;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};

const READ_TIMEOUT: Duration = Duration::from_secs(15);
const BACKEND_TIMEOUT: Duration = Duration::from_secs(30);

const MAX_REQUEST: usize = 256 * 1024;

pub async fn serve(config: Config) -> Result<(), String> {
    config.validate().map_err(|e| e.to_string())?;
    let bind = config.ingress_bind.clone().ok_or("ingress_bind_required")?;
    let bearer = config
        .runtime_bearer
        .clone()
        .ok_or("runtime_bearer_required")?;
    let caller = config.caller_id.clone().ok_or("caller_id_required")?;
    let backend_token = config
        .backend_auth_token
        .clone()
        .ok_or("backend_auth_token_required")?;
    let bind_addr = bind
        .parse::<std::net::SocketAddr>()
        .map_err(|_| "invalid_ingress_bind")?;
    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|_| "ingress_bind_failed")?;
    let shared = Arc::new(config);
    loop {
        let (socket, _) = listener
            .accept()
            .await
            .map_err(|_| "ingress_accept_failed")?;
        let cfg = shared.clone();
        let bearer = bearer.clone();
        let caller = caller.clone();
        let backend_token = backend_token.clone();
        tokio::spawn(async move {
            let mut socket = socket;
            if let Err(code) = handle(&mut socket, cfg, bearer, caller, backend_token).await {
                eprintln!("sidecar request failed: {code}");
                // Requests that fail before an HTTP response is written get a
                // bounded fallback response. `write_error` returns `Ok(())`
                // after successfully writing a response, so this branch never
                // appends a second HTTP response to an already completed one.
                if code != "response_already_started" {
                    let _ = write_error(&mut socket, 502, "sidecar_request_failed").await;
                }
            }
        });
    }
}

async fn handle(
    mut socket: &mut tokio::net::TcpStream,
    config: Arc<Config>,
    bearer: String,
    caller: String,
    backend_token: String,
) -> Result<(), String> {
    let mut bytes = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    let header_end;
    loop {
        let n = timeout(READ_TIMEOUT, socket.read(&mut chunk))
            .await
            .map_err(|_| "ingress_read_timeout")?
            .map_err(|_| "ingress_read_failed")?;
        if n == 0 {
            return Err("ingress_connection_closed".into());
        }
        bytes.extend_from_slice(&chunk[..n]);
        if bytes.len() > MAX_REQUEST {
            return write_error(&mut socket, 413, "request_too_large").await;
        }
        if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
    }
    let head = String::from_utf8(bytes[..header_end].to_vec()).map_err(|_| "invalid_http")?;
    let mut lines = head.split("\r\n");
    let first = lines.next().ok_or("invalid_http")?;
    let mut first_parts = first.split_whitespace();
    let method = first_parts.next().ok_or("invalid_http")?;
    let target = first_parts.next().ok_or("invalid_http")?;
    let version = first_parts.next().ok_or("invalid_http")?;
    if version != "HTTP/1.1"
        || first_parts.next().is_some()
        || target.starts_with("http://")
        || target.starts_with("https://")
    {
        return write_error(&mut socket, 400, "invalid_target").await;
    }
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (k, v) = line.split_once(':').ok_or("invalid_http")?;
        let key = k.trim().to_ascii_lowercase();
        if headers.contains_key(&key) {
            return write_error(&mut socket, 400, "duplicate_header").await;
        }
        headers.insert(key, v.trim().to_string());
    }
    if headers.contains_key("transfer-encoding") {
        return write_error(&mut socket, 400, "unsupported_transfer_encoding").await;
    }
    let length = match headers.get("content-length") {
        Some(value) => match value.parse::<usize>() {
            Ok(length) => length,
            Err(_) => return write_error(&mut socket, 400, "invalid_content_length").await,
        },
        None => 0,
    };
    if length > MAX_REQUEST || header_end + length > MAX_REQUEST {
        return write_error(&mut socket, 413, "request_too_large").await;
    }
    while bytes.len() < header_end + length {
        let n = timeout(READ_TIMEOUT, socket.read(&mut chunk))
            .await
            .map_err(|_| "ingress_read_timeout")?
            .map_err(|_| "ingress_read_failed")?;
        if n == 0 {
            return Err("ingress_connection_closed".into());
        }
        bytes.extend_from_slice(&chunk[..n]);
    }
    let body = bytes[header_end..header_end + length].to_vec();
    let encoded = headers
        .get("x-oan-envelope")
        .ok_or("missing_oan_envelope")?;
    let envelope: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| "invalid_oan_envelope")?,
    )
    .map_err(|_| "invalid_oan_envelope")?;
    let request_id = headers
        .get("x-oan-request-id")
        .ok_or("missing_oan_request_id")?
        .clone();
    let callback_did = headers.get("x-oan-callback-did").cloned();
    let payload_digest = format!("sha256:{:x}", sha2::Sha256::digest(&body));
    let runtime = AuthenticatedRuntimeConnector::new(
        local_runtime_transport(
            &config.runtime_endpoint,
            config.runtime_owner_uid,
            config.runtime_owner_pid,
        )?,
        bearer,
        caller.clone(),
        config.tenant_id.clone(),
    )
    .map_err(|_| "runtime_credentials_invalid")?;
    let principal = if let Some(callback) = callback_did.as_deref() {
        let context = runtime
            .verify_authenticated_callback(
                &envelope,
                &config.resource_did,
                &request_id,
                &payload_digest,
                callback,
            )
            .await
            .map_err(|e| {
                eprintln!("runtime callback verification failed: {e}");
                "runtime_verification_failed"
            })?;
        if context.audience_did != config.resource_did
            || context.request_id != request_id
            || context.payload_digest != payload_digest
            || context.callback_did.as_deref() != Some(callback)
        {
            return write_error(&mut socket, 401, "callback_binding_mismatch").await;
        }
        crate::VerifiedPrincipal::from_context(
            context,
            &config.resource_did,
            &request_id,
            &payload_digest,
            caller.clone(),
            config.tenant_id.clone(),
        )
        .map_err(|e| {
            eprintln!("runtime verification failed: {e}");
            "runtime_verification_failed"
        })?
    } else {
        match crate::verify_inbound_authenticated(
            &runtime,
            &envelope,
            &config.resource_did,
            &request_id,
            &payload_digest,
        )
        .await
        {
            Ok(principal) => principal,
            Err(error) => {
                eprintln!("inbound verification failed: {error}");
                return Err("runtime_verification_failed".into());
            }
        }
    };
    eprintln!(
        "verified principal subject={} request={}",
        principal.subject_did(),
        principal.request_id()
    );
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(BACKEND_TIMEOUT)
        .build()
        .map_err(|_| "backend_client_init_failed")?;
    let base = reqwest::Url::parse(&config.backend_url).map_err(|_| "backend_url_invalid")?;
    let target_url = reqwest::Url::parse(&format!("http://sidecar.invalid{target}"))
        .map_err(|_| "backend_target_invalid")?;
    let mut url = base.clone();
    url.set_path(target_url.path());
    url.set_query(target_url.query());
    let mut req = client
        .request(method.parse().map_err(|_| "invalid_method")?, url)
        .body(body);
    for (k, v) in strip_untrusted_identity_headers(
        &headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>(),
    ) {
        if k != "content-length" && k != "host" && k != "x-oan-envelope" {
            req = req.header(k, v);
        }
    }
    req = req
        .header("x-oan-sidecar-token", backend_token)
        .header("x-oan-verified-principal", principal.subject_did())
        .header("x-oan-request-id", principal.request_id());
    // Once the request has been verified, split the ingress socket. Do not
    // treat an EOF on the read half before the backend responds as a client
    // disconnect: HTTP clients such as urllib may half-close their upload
    // side immediately after sending a complete request. The backend request
    // must therefore be allowed to finish first; the read half is used for
    // disconnect detection while streaming the response below.
    let (mut client_reader, mut client_writer) = socket.split();
    let response = match req.send().await {
        Ok(response) => response,
        Err(error) => {
            eprintln!("backend request failed: {error}");
            let _ = write_error(&mut client_writer, 502, "backend_unavailable").await;
            return Ok(());
        }
    };
    let status = response.status();
    if config.response_signing {
        let status = response.status();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();
        let bytes = response.bytes().await.map_err(|_| "response_read_failed")?;
        if bytes.len() > MAX_REQUEST * 4 {
            return write_error(&mut socket, 502, "response_too_large").await;
        }
        let response_digest = format!("sha256:{:x}", sha2::Sha256::digest(&bytes));
        let response_intent = serde_json::json!({
            "kind": "sidecar-response",
            "requestId": request_id,
            "requestPayloadDigest": payload_digest,
            "payloadDigest": response_digest,
            "audienceDid": principal.subject_did(),
            "originalCallerDid": principal.subject_did(),
            "targetResourceDid": config.resource_did,
            "callbackDid": callback_did,
            "status": status.as_u16(),
            "operation": "response"
        });
        let signed_response = runtime
            .sign_authenticated(&response_intent)
            .await
            .map_err(|_| "response_signing_failed")?;
        let encoded_response = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&signed_response).map_err(|_| "response_signing_failed")?);
        let head = format!(
            "HTTP/1.1 {}\r\nContent-Length: {}\r\nContent-Type: {}\r\nX-OAN-Response-Envelope: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
            status.as_u16(), bytes.len(), content_type, encoded_response
        );
        socket
            .write_all(head.as_bytes())
            .await
            .map_err(|_| "response_write_failed")?;
        socket
            .write_all(&bytes)
            .await
            .map_err(|_| "response_write_failed")?;
        return Ok(());
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let mut stream = response.bytes_stream();
    let status_line = format!("HTTP/1.1 {}\r\nTransfer-Encoding: chunked\r\nContent-Type: {content_type}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n", status.as_u16());
    client_writer
        .write_all(status_line.as_bytes())
        .await
        .map_err(|_| "response_already_started")?;
    let peer_closed = wait_for_client_close(&mut client_reader);
    tokio::pin!(peer_closed);
    loop {
        let chunk = tokio::select! {
            next = stream.next() => match next {
                Some(chunk) => chunk.map_err(|_| "response_already_started")?,
                None => break,
            },
            closed = &mut peer_closed => {
                let _ = closed;
                return Err("response_already_started".into());
            }
        };
        let prefix = format!("{:x}\r\n", chunk.len());
        client_writer
            .write_all(prefix.as_bytes())
            .await
            .map_err(|_| "response_already_started")?;
        client_writer
            .write_all(&chunk)
            .await
            .map_err(|_| "response_already_started")?;
        client_writer
            .write_all(b"\r\n")
            .await
            .map_err(|_| "response_already_started")?;
    }
    client_writer
        .write_all(b"0\r\n\r\n")
        .await
        .map_err(|_| "response_already_started")?;
    Ok(())
}

async fn wait_for_client_close(reader: &mut tokio::net::tcp::ReadHalf<'_>) -> Result<(), String> {
    let mut probe = [0u8; 1];
    match reader.read(&mut probe).await {
        // A client may half-close its upload direction after sending a
        // complete request (urllib and several streaming clients do this).
        // EOF on the read half therefore does not prove that the peer has
        // abandoned the response. Keep the observer pending and let a write
        // failure detect a real disconnect.
        Ok(0) => std::future::pending().await,
        Ok(_) => Err("client_protocol_data_after_request".into()),
        Err(_) => std::future::pending().await,
    }
}

async fn write_error<W: AsyncWrite + Unpin>(
    socket: &mut W,
    status: u16,
    code: &str,
) -> Result<(), String> {
    let body = format!("{{\"error\":\"{}\"}}", code);
    let head=format!("HTTP/1.1 {}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",status,body.len());
    socket
        .write_all(head.as_bytes())
        .await
        .map_err(|_| "ingress_write_failed")?;
    socket
        .write_all(body.as_bytes())
        .await
        .map_err(|_| "ingress_write_failed")?;
    Ok(())
}
