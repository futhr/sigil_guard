# SigilGuard Threat Model

This guide renders the normative R.06 control mapping for operators and
integrators. It does not expand any claim beyond the source research note:
SigilGuard is an embedded library that controls MCP and agent-tool boundaries,
not host authentication, transport security, sandbox execution, model behavior,
or ecosystem tooling.

## Control Mapping

| # | Attack | ASI class | SigilGuard control | Claim | Test |
|---|--------|-----------|--------------------|-------|------|
| 1 | Prompt injection via tool results, including pull-request title hijack | ASI01 | Result-phase scanner pipeline, streaming holdback, sink-aware output contracts, and boundary policy tainting for `tool_result` origin. | mitigates | TM.01 |
| 2 | Tool poisoning via descriptions or metadata | ASI02, ASI04 | Capability-manifest digest pinning over description, schema, and annotation digests; drift rejection. | mitigates | TM.02 |
| 3 | Line jumping before invocation through `tools/list` | ASI01, ASI02 | `tools/list` output is verified against pinned manifest digests before content enters model context. | mitigates | TM.03 |
| 4 | Schema injection through adversarial required params | ASI02, ASI03 | Input-schema digest binding, schema validation, and adversarial-required-param indicators bound into the manifest digest. | mitigates + detects | TM.04 |
| 5 | Rug pull or TOFU drift | ASI04 | Digest-pinned manifests with drift rejection; `tools/list_changed` drops cached approvals and forces reverification. | mitigates | TM.05 |
| 6 | Confused deputy, including consent-cookie replay | ASI03 | Attestations bind audience, resource, and actor; ReplayStore scopes nonce replay; DSSE expiry bounds reuse. | mitigates (partial) | TM.06 |
| 7 | Token passthrough | ASI03 | Gateway audience/resource mismatch is an explicit block; attestation records intended audience. | mitigates | TM.07 |
| 8 | Session hijacking through resumable streams and `tools/list_changed` | ASI03, ASI02 | `tools/list_changed` invalidates cached approvals; per-action nonce/replay scope and audit records session boundaries. | detects (partial) | TM.07 |
| 9 | Memory and context poisoning | ASI06 | Model-ingress gating sends retrieved memory/context through scanner and trust-zone policy before model exposure; ingested records carry digest provenance. | mitigates + detects | TM.08 |
| 10 | Lethal-trifecta dataflow | ASI01, ASI02, ASI05 | Boundary policy rule over private data, untrusted origin, and external sink; sink-aware output contracts. | mitigates | TM.09 |
| 11 | Unexpected code execution via tool or agent output | ASI05 | Sink-aware output contracts deny untrusted-origin content into execution sinks; confirmation binds action digest including `sandbox_id`. | mitigates (dataflow); out-of-scope (the runtime that executes) | TM.09 |
| 12 | A2A impersonation | ASI07, ASI10 | Agent-card verification against trust-bundle issuers; unknown-agent quarantine default. | mitigates | TM.10 |
| 13 | A2A delegation abuse | ASI03, ASI07 | Delegation-chain validation over act-claim nesting, maximum depth, and trust derivation across hops. | mitigates | TM.10 |
| 14 | Supply-chain backdoor in a package | ASI04 | Manifest and bundle digest drift detection on changed versions; egress dataflow policy flags hidden external sinks. | detects (partial) | TM.11 |
| 15 | Supply-chain hosting-infra path traversal | ASI04 | Trust-bundle verification and quarantine when redistributed bundles or manifests fail signature or drift from pinned digests. | out-of-scope (infra); detects drift | TM.11 |
| 16 | Ecosystem tooling RCE in MCP Inspector | ASI05 | No prevention claim; audit chain records boundary decisions around affected tools. | out-of-scope | TM.11 |
| 17 | Ecosystem tooling RCE in mcp-remote | ASI05 | No prevention claim; vulnerable clients are host-owned transport tooling. | out-of-scope | TM.11 |
| 18 | Config-swap persistence in an IDE | ASI04, ASI05 | SigilGuard cannot patch the IDE; the analogous pattern is digest-pinned reapproval after manifest or config change. | out-of-scope (the IDE); mitigates the analogous pattern | TM.05 |
| 19 | Cascading agent failures | ASI08 | Per-hop attestation and delegation-chain evidence let operators reconstruct propagation; no automatic containment claim. | partial (evidence-only) | TM.12 |
| 20 | Rogue agents operating outside the envelope | ASI10 | Agent-card and delegation-chain verification deny unknown or unbundled agents at the boundary; audit flags out-of-envelope actions. | detects-at-boundary | TM.10 |
| 21 | Human-agent trust exploitation through spoofed or forged approval | ASI09 | Confirmation tokens bind the exact action digest including `sandbox_id`; single-use and TTL defeat replayed or forged approvals. | mitigates (the token); out-of-scope (human judgment) | TM.06 |
| 22 | Repudiation, audit tamper, or truncation | ASI08, ASI03 | Audit HMAC chain, Merkle checkpoints, inclusion and consistency proofs, and external anchors make tamper and truncation detectable. | mitigates + detects | TM.12 |

Summary: the table has 22 rows. Twelve rows claim mitigation, some jointly with
detection. Three rows are detection or partial evidence claims. Seven rows are
out-of-scope, evidence-only, or analogous-pattern claims. Out-of-scope rows may
still record evidence or detect drift, but they do not claim prevention.

## Claim Levels

- **mitigates** — SigilGuard prevents the attack from producing its intended
  effect at the boundary it controls, deterministically and without model
  cooperation. The malicious input must be blocked, quarantined, or forced
  through confirmation.
- **detects** — SigilGuard cannot prevent the root cause because it lives in a
  host-owned surface, but it emits a deterministic, tamper-evident signal such
  as digest drift, quarantine indication, replay rejection, or audit evidence.
- **partial** — SigilGuard covers one facet, such as replay, drift, or
  propagation evidence, but a host-owned surface is required for complete
  coverage. The partial boundary must be explicit.
- **out-of-scope** — The vulnerability lives entirely outside SigilGuard's
  ownership, such as ecosystem tooling, IDEs, transport clients, or human
  judgment. SigilGuard may record evidence, but it must not claim prevention.
- **detects-at-boundary** — SigilGuard detects and rejects the condition at the
  boundary it observes, while behavior fully outside that boundary remains
  host-owned.

## Host-Owned Exclusions

SigilGuard is a library. These surfaces remain the host application's
responsibility:

- **OAuth flows and token issuance** — SigilGuard consumes an already-issued
  identity or audience and binds it into attestations. It does not run the
  authorization server, mint tokens, or manage consent cookies.
- **Session and transport security** — TLS, stream resumption, WebSocket auth,
  and session lifecycle belong to the host transport. SigilGuard adds
  per-action nonce/replay and `tools/list_changed` invalidation as assists.
- **Sandbox execution** — SigilGuard requires sandbox identity and isolation
  level as attested inputs and can fail closed on unsafe boundaries. It does
  not create, run, or harden the sandbox itself.
- **Memory-store implementations** — SigilGuard gates content at model ingress
  and can bind provenance digests. The vector store, RAG index, and eviction
  policy are host-owned.
- **Model behavior** — SigilGuard is deterministic and never relies on the
  model to refuse an attack. Model alignment and refusal behavior are out of
  scope.
- **Ecosystem tooling and IDEs** — SigilGuard cannot patch vulnerable tools,
  IDE extensions, or transport clients. It assumes compromised tooling is
  possible and records boundary evidence around the affected operations.

## Test Families

| ID | Family | Primary rows |
|----|--------|--------------|
| TM.01 | Prompt injection via tool results | 1 |
| TM.02 | Tool poisoning through descriptions and metadata | 2 |
| TM.03 | Line jumping through pre-invocation manifest exposure | 3 |
| TM.04 | Schema injection | 4 |
| TM.05 | Rug pull, TOFU drift, and analogous config swap | 5, 18 |
| TM.06 | Confused deputy and consent replay | 6, 21 |
| TM.07 | Token passthrough and session hijacking | 7, 8 |
| TM.08 | Memory poisoning at model ingress | 9 |
| TM.09 | Lethal-trifecta dataflow and execution-sink boundaries | 10, 11 |
| TM.10 | A2A impersonation and delegation abuse | 12, 13, 20 |
| TM.11 | Supply-chain tamper, revoked bundles, and tooling evidence | 14, 15, 16, 17 |
| TM.12 | Cascading failures, repudiation, audit tamper, and truncation | 19, 22 |

Every mitigation or detection row maps to a threat-model test module under
`test/sigil_guard/threat_model/`. Evidence-only and out-of-scope rows are tested
only for the signals SigilGuard actually owns.
