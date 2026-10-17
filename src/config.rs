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
}
impl Config {
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
            || !matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"))
        {
            return Err(BoundaryError::InvalidConfig);
        }
        if !((self.runtime_endpoint.starts_with("unix:/") && self.runtime_endpoint.len() > 6)
            || (self.runtime_endpoint.starts_with("pipe:") && self.runtime_endpoint.len() > 5))
        {
            return Err(BoundaryError::InvalidConfig);
        }
        Ok(())
    }
}
