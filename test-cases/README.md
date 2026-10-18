<!-- Copyright (c) 2026 OpenAgenet contributors -->
<!-- Initial author: JINLIANG XU; Email: jlxufly@gmail.com -->
# Sidecar integration test cases

The Sidecar provides a loopback protected HTTP ingress, versioned authenticated Runtime IPC, identity-header filtering and a Runtime verification boundary. The backend credential is injected only after verification; direct fixture access must fail. These cases exercise those functions against all five real lab resources and keep stream/callback acceptance separate from synchronous proxy acceptance.

## Run

```sh
cargo test --test lab_cases
cargo test
cargo fmt --check
```

`tests/lab_cases.rs` exposes `test-cases/lab/cases.rs` as a normal Cargo integration test. `fixtures.rs` loads **public** manifest/DID documents from the lab; no Rust case loads private keys or makes network calls. Two explicit ignored cases represent absent real integration; forcing them with `cargo test --test lab_cases -- --include-ignored` fails rather than certifying an unimplemented feature.

## Cases

| ID | Scenario | Action and required result | State |
|---|---|---|---|
| SC-01 | All five services, fixed resource DID and loopback port/path | Build Config from actual document/manifest; validate exact endpoint mapping; reject malformed DID, remote backend and HTTP Runtime endpoint | Implemented; correct default IPC is a test-only socket name, not a deployed daemon |
| SC-02 | Forged identity/forwarding headers alongside MCP/OAuth headers | Strip case-insensitive reserved identity headers; preserve Content-Type, MCP protocol header and Authorization | Implemented header-function check, not HTTP middleware |
| SC-03 | Trusted Runtime context binding | For each target, reject returned wrong audience/request ID/body digest/malformed subject; no simulated handler invocation. Valid context yields exact principal | Implemented with explicitly named `ContextDouble`; not crypto or IPC verification |
| SC-04 | Runtime missing; envelope claims verified | All targets rejected; capabilities describe the implemented protected boundary, but no Runtime result means zero authorization | Implemented fail-closed behavior |
| SC-05 | A2A A→B, A2A→MCP, Hermes A→B through actual Sidecar | Real Runtime authenticates caller, evidence/session/proof; native client through protected ingress; reject faults before ledger effects; direct backend bypass impossible for attacker fixture; callback DID is bound by Runtime; signed response verified by caller | Unit/backend isolation and lab-side cross-process A2A/MCP adapters are executable on Ubuntu Unix IPC; pinned Hermes and full response/stream verification remain separate |
| SC-06 | A2A/Hermes streams, MCP events and cancellation | Maintain native framing/backpressure; verify ordered signed events/terminal state; close on invalid or truncated stream; cleanup on disconnect | Runtime stream verifier and Sidecar chunked forwarding are implemented; full cross-process stream assertions remain lab/Ubuntu acceptance |
| SC-07 | Outbound versus inbound profile | Trusted local host signs exact method/path/operation/body with resource key; target and response checks bind DID and request digest; no controller key substitution | Runtime-mediated outbound signing IPC and Sidecar target/body binding are implemented; multi-hop and Hermes outbound remain separate |
| SC-08 | Same-host bypass / restart / Runtime outage | Dedicated process/user or authenticated backend IPC; disconnect/restart retains replay; unavailable verifier returns stable rejection and zero effects; no L2 downgrade | Planned infrastructure acceptance; loopback alone is not isolation |
| SC-09 | Coexistence and host limits | Valid MCP initialize/list/call and A2A Card/task/query/cancel preserved; OAuth authorization remains additional; oversized body, invalid frame and timeouts are bounded | Planned real network acceptance |
| SC-10 | MCP stdio and Skill invocation | Verify explicit supported transport capability or reject; no remote-auth claim for stdio; Skill protected calls use same core | Planned capability-specific coverage, no invented stdio proxy support |

SC-03's digest is a labelled test token, not a real payload SHA-256: Runtime cryptography is deliberately outside that unit's scope. The verified subject is supplied by the trusted connector contract; Sidecar currently cannot independently prove the trusted connector's claimed subject. Full acceptance must use a real authenticated Runtime and expected peer policy. A passing double must never enable `runtimeConnector` or `mutualAuthentication` capabilities.

## Next executable integration

The versioned authenticated Runtime IPC and local protected HTTP ingress are implemented. Keep the native backend unavailable to the simulated untrusted caller with a per-sidecar credential; loopback alone is not the isolation proof. The test adapter must invoke real Sidecar APIs, not inject a VerifiedPrincipal itself. Use MCP `record` and A2A `record:<marker>` and read the ledger independently. The `sidecar-a2a-l2` and `sidecar-mcp-l2` adapters start the real Runtime IPC, Sidecar ingress and native backend in a run-owned directory on Ubuntu, and exercise callback binding, A2A chunked stream forwarding, MCP cancellation and direct-backend rejection. Their forged callback and bypass cases remain negative. Linux socket owner/mode checks are enforced by the connector; deployment should additionally run Runtime and Sidecar under separate least-privilege users where host policy requires it. No production OAN service or firewall changes belong in these unit cases.

## Shared laboratory contract

Use a sibling checkout of `oan-agent-integration-lab`, or set `OAN_LAB_ROOT` to its absolute path. Baseline: lab commit `35ad408`, five resource packages `0.1.0.2`; later metadata changes are read from the manifest rather than fixed hashes. Node 22.13+ and Rust 1.98+ are the component baselines. Keep dependency repositories (`oan-sdk-ts`, `oan-protocol-common`) beside these repositories as required by their existing build configuration.

| Lab actor | Resource kind / wire protocol | Same-host service | Controller |
|---|---|---|---|
| a2a-a | agent_service / A2A 1.0 | http://127.0.0.1:4101/ | controller-a |
| a2a-b | agent_service / A2A 1.0 | http://127.0.0.1:4102/ | controller-a |
| mcp | mcp_server / SDK-negotiated MCP Streamable HTTP | http://127.0.0.1:4201/mcp | controller-a |
| hermes-a | agent_service / pinned native Hermes A2A adapter | http://127.0.0.1:4301/ | controller-b |
| hermes-b | agent_service / pinned native Hermes A2A adapter | http://127.0.0.1:4302/ | controller-b |

`config/oan-identities.json` is the source of real DIDs and relative paths. Reuse the resource key for peer communication; controller keys authorize registration/document updates and are not proxy delegation. These tests never create new DIDs, register resources, change production nodes, deploy services, or print private keys. Do not copy lab keys into these component repositories. The private lab checkout retains the owner-approved test keys.

Default tests are offline. A missing lab fixture is a **failure**, not a synthetic identity fallback. Scheduled network or server tests require a separately prepared lab. Loopback always means the caller's current host. Existing shared OS-user fixtures cannot prove isolation against a hostile local process.

## Result and evidence rules

- `implemented`: executable test of existing public component code. State the exact scope; a passing boundary unit test is not a proxy/handshake pass.
- `opt-in`: requires an explicit switch, public read-only network requests or a prepared external lab.
- `blocked`: named missing implementation; displayed as skipped/ignored, never counted as passed. Do not remove the gate until the real implementation and acceptance assertions exist.
- Unit test doubles only exercise specified binding gates. A pre-authenticated session fixture does not prove a handshake. Loading a saved VC does not verify the issuer or governance chain.
- L0 is registration/discovery/endpoint resolution. L1 additionally needs real DID/VC/trust/status checks. Independent mutual verification needs signed peer possession and final confirmation. L2 additionally binds actual requests and responses, policy, time, audience, correlation and replay, and prevents bypass before effects.
- No test may silently downgrade L2 to L1 or native protocol success. Expired/unavailable evidence is unknown/rejected, never authenticated.

## Future end-to-end fault matrix

For each enabled A2A, MCP HTTP, MCP stdio and Hermes entry point: positive call executes exactly once; altered request, wrong audience, wrong sender, controller-key substitution, wrong operation/service/session/request, expired proof, forged principal and bypass execute zero times. Replay executes only its first valid attempt. Response tampering/substitution executes once but the caller rejects the result as untrusted. Use unique markers and read the actual lab ledger separately from component reports. Responses bind the request digest and peer DID; streaming tests bind task/request, sequence, previous digest and signed terminal state, including truncation, reordering, cancellation and disconnect. Restart tests require durable replay state and reject a previously consumed nonce after process restart.

Future live Hermes tests use the pinned upstream adapter in transport mode, no model. Full gateway/model behavior and autonomous Skill execution are separate optional checks. MCP stdio must use the official client and process ownership rules; it is not remote mutual authentication merely because messages carry DIDs. Existing OAuth/Bearer and MCP headers must retain their protocol semantics.
