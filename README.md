<!-- Copyright (c) 2026 OpenAgenet contributors -->
<!--
Initial author: JINLIANG XU
Email: jlxufly@gmail.com
-->

# OAN Identity Sidecar

A local OAN identity boundary component deployed beside existing agents or services. It provides request signing, response verification, and verified-principal injection for MCP, HTTP, and other services that cannot embed the Identity Runtime directly.

`oan-identity-sidecar` does not maintain a separate identity system and does not duplicate OAN registration, Discovery, DID hashing, or signing logic. It calls `oan-identity-runtime` through protected local IPC or loopback interfaces.

## Scope

The current G5 implementation supports:

- submitting structured signing intents for outbound requests, with identity selection and signing performed by the Runtime;
- verifying inbound OAN envelopes, audience, time windows, nonces, digests, and signatures;
- verifying responses, streaming events, and tool results;
- injecting a read-only `VerifiedPrincipal` into the backend;
- removing or rejecting client-supplied forged identity headers;
- a loopback protected HTTP ingress for MCP, ordinary HTTP and A2A-compatible request bodies;
- versioned Unix-socket Runtime IPC with bearer, caller, tenant, request digest and callback binding;
- Windows named-pipe Runtime IPC (`pipe:\\\\.\\pipe\\<name>`) with the same verified message contract;
- Windows pipe connection pinned to the configured Runtime process ID (`runtimeOwnerPid`), in addition to Runtime bearer and caller binding;
- owner-only Unix-socket ACL and optional expected owner UID checks before every IPC connection;
- Runtime-mediated outbound signing, with method/target/body/request binding and redirect disabled;
- bounded chunked response forwarding with client-disconnect detection and backend timeout;
- backend credential injection so direct fixture access fails closed.

For a Windows cross-language IPC check, build the sibling Runtime with
`npm --prefix ../oan-identity-runtime run build`, then run
`cargo test --test windows_pipe -- --include-ignored`. This starts a local
Node Runtime test listener and checks callback and response-signing IPC.

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

A buildable G5 boundary implementation is present. The lab supplies Ubuntu-only cross-process A2A/MCP adapters that exercise protected ingress, Runtime IPC, callback binding, response streaming, cancellation and direct-backend rejection. Full Linux peer-credential verification beyond socket owner/mode checks, pinned Hermes outbound execution and complete multi-hop Gateway paths remain separate acceptance work. Detailed design, development planning, and framework reviews are maintained separately in `oan-design-docs`. Source code uses English by default.

## License

This repository is licensed under `Apache-2.0` to support OAN ecosystem adoption.


Community Skill identity verification does not require this component. It uses the local Runtime/SDK workflow to exchange public challenge messages. This component retains its protocol/network enforcement role; its presence alone does not implement mutual authentication. Dedicated Hermes/OpenClaw plugins are not prerequisites for their compatible Skill-based path.

## Integration test cases

See [test-cases/README.md](test-cases/README.md) for the lab-based scenario matrix, executable cases, run commands and explicit blocked end-to-end gates. Test identities are reused from `oan-agent-integration-lab`; no identity keys are copied into this repository.

## Native protocol integration boundary

The protected HTTP reference has been exercised in a Windows-to-Ubuntu
A2A-to-MCP two-hop deployment with real Runtime IPC. This component forwards
native protocol bodies and asks Runtime to verify/sign; it does not own resource
keys, registration workflows or business handlers. Configure private backends
with a distinct credential and bind native task/session ownership to the
Runtime-verified peer DID. Public ingress deployment and additional protocols
retain their own acceptance requirements.

Signed SSE responses are forwarded incrementally with an OAN terminal proof.
Protocol clients can install Runtime `createVerifiedHttpFetch` to validate and
remove that proof without modifying their SDK. Interrupted streams never receive
a second HTTP response or an automatic business retry.
