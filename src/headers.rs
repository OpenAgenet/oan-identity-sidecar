// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

/// Reserved identity/forwarding headers cannot arrive from an untrusted caller.
pub fn is_reserved_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.starts_with("x-oan-")
        || name.starts_with("oan-")
        || name == "forwarded"
        || name.starts_with("x-forwarded-")
        || name == "x-verified-principal"
}
pub fn strip_untrusted_identity_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| !is_reserved_header(name))
        .cloned()
        .collect()
}
