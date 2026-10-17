<!-- Copyright (c) 2026 OpenAgenet contributors -->
<!--
Initial author: JINLIANG XU
Email: jlxufly@gmail.com
-->

# OAN Identity Sidecar

A local OAN identity boundary component deployed beside existing agents or services. It provides request signing, response verification, and verified-principal injection for MCP, HTTP, and other services that cannot embed the Identity Runtime directly.

`oan-identity-sidecar` does not maintain a separate identity system and does not duplicate OAN registration, Discovery, DID hashing, or signing logic. It calls `oan-identity-runtime` through protected local IPC or loopback interfaces.

## Scope

The first Sidecar release supports:

- submitting structured signing intents for outbound requests, with identity selection and signing performed by the Runtime;
- verifying inbound OAN envelopes, audience, time windows, nonces, digests, and signatures;
- verifying responses, streaming events, and tool results;
- injecting a read-only `VerifiedPrincipal` into the backend;
- removing or rejecting client-supplied forged identity headers;
- providing a thin boundary for MCP Streamable HTTP, ordinary HTTP, and later A2A deployments.

stdio proves only a local process boundary. Without a remote challenge and message signatures, the Sidecar must not report successful remote mutual identity verification.

## Boundary

The Sidecar handles protocol boundaries, request correlation, and verification context. The Runtime handles identity catalogs, keys, policy, sessions, and audit. The Sidecar never handles long-term private keys, does not expose arbitrary `sign(bytes)`, and does not replace a resource business identity with its controller identity.

It can run on a user- or enterprise-controlled host, container, or private network. OAN does not host user private keys or provide a centralized signing service by default.

## Integration

```text
Agent / MCP Server / HTTP Service
              │
              ▼
      OAN Identity Sidecar
              │ protected IPC
              ▼
      OAN Identity Runtime
              │
              ▼
    signed request / verified principal
```

## Development status

A buildable development framework is now present. This is not yet a production identity service or a complete mutual-authentication implementation. Detailed design, development planning, and framework reviews are maintained separately in `oan-design-docs`. Source code uses English by default.

## License

This repository is licensed under `Apache-2.0` to support OAN ecosystem adoption.


Community Skill identity verification does not require this component. It uses the local Runtime/SDK workflow to exchange public challenge messages. This component retains its protocol/network enforcement role; its presence alone does not implement mutual authentication. Dedicated Hermes/OpenClaw plugins are not prerequisites for their compatible Skill-based path.
