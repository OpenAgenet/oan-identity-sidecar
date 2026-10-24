// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use crate::BoundaryError;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub resource_did: String,
    pub backend_url: String,
    pub runtime_endpoint: String,
    #[serde(default)]
    pub ingress_bind: Option<String>,
    #[serde(default)]
    pub backend_auth_token: Option<String>,
    #[serde(default)]
    pub runtime_bearer: Option<String>,
    #[serde(default)]
    pub caller_id: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub runtime_owner_uid: Option<u32>,
    #[serde(default)]
    pub runtime_owner_pid: Option<u32>,
    #[serde(default)]
    pub response_signing: bool,
}
impl Config {
    /// Serving preflight checks local configuration only, never starts or
    /// cleans business processes. OS isolation remains deployment-owned.
    pub fn validate_serving(&self) -> Result<(), BoundaryError> {
        self.validate()?;
        if self.ingress_bind.is_none()
            || self.runtime_bearer.is_none()
            || self.backend_auth_token.is_none()
            || self
                .caller_id
                .as_ref()
                .is_none_or(|value| value.trim().is_empty())
        {
            return Err(BoundaryError::InvalidConfig);
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<(), BoundaryError> {
        if oan_did_oan::DidOan::parse(&self.resource_did).is_err()
            || self.runtime_endpoint.is_empty()
        {
            return Err(BoundaryError::InvalidConfig);
        }
        let url = url::Url::parse(&self.backend_url).map_err(|_| BoundaryError::InvalidConfig)?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || !matches!(url.host_str(), Some("127.0.0.1" | "::1" | "localhost"))
        {
            return Err(BoundaryError::InvalidConfig);
        }
        if !((self.runtime_endpoint.starts_with("unix:/") && self.runtime_endpoint.len() > 6)
            || (self.runtime_endpoint.starts_with(r"pipe:\\.\pipe\")
                && self.runtime_endpoint.len() > r"pipe:\\.\pipe\".len()))
        {
            return Err(BoundaryError::InvalidConfig);
        }
        if let Some(bind) = &self.ingress_bind {
            let url = url::Url::parse(&format!("http://{bind}"))
                .map_err(|_| BoundaryError::InvalidConfig)?;
            if !matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"))
                || url.path() != "/"
                || url.port().is_none()
            {
                return Err(BoundaryError::InvalidConfig);
            }
        }
        for token in [&self.backend_auth_token, &self.runtime_bearer] {
            if let Some(value) = token {
                if !(32..=512).contains(&value.len()) {
                    return Err(BoundaryError::InvalidConfig);
                }
            }
        }
        if let Some(caller) = &self.caller_id {
            if caller.is_empty() || caller.len() > 256 {
                return Err(BoundaryError::InvalidConfig);
            }
        }
        if self.runtime_endpoint.starts_with("unix:") && self.runtime_owner_uid.is_none() {
            return Err(BoundaryError::InvalidConfig);
        }
        if self.runtime_endpoint.starts_with("pipe:") && self.runtime_owner_pid.is_none() {
            return Err(BoundaryError::InvalidConfig);
        }
        Ok(())
    }
}
