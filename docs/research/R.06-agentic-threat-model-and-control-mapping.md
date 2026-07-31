---
sigil_guard:
  id: "R.06"
  topic: "Agentic Threat Model And Control Mapping"
  category: research
  status: complete
  created: "2026-07-02"
  updated: "2026-07-02"
  decision: adopted
  tags:
    [
      "threat-model",
      "owasp-agentic",
      "mcp-security",
      "prompt-injection",
      "supply-chain",
      "lethal-trifecta",
      "control-mapping"
    ]
---

# R.06 - Agentic Threat Model And Control Mapping

## Executive Summary

This note is the normative SigilGuard v3 threat model. It maps the OWASP Top 10
for Agentic Applications 2026 (ASI01-ASI10) and the named mid-2026 MCP attack
taxonomy to specific SigilGuard v3 controls, and it assigns every attack a claim
level (mitigates / detects / out-of-scope) plus a named M5 test family
(TM.01-TM.12). The control-mapping table is the heart of the document; the
architecture-rationale and positioning sections justify why the controls are a
deterministic policy kernel rather than model-level guardrails alone.

The decision is **adopted**. This threat model is the single source of truth for
"what SigilGuard claims against which attack." Every row marked `mitigates` or
`detects` MUST have a green test module under `test/sigil_guard/threat_model/`
before the 1.0.0 release (milestone M5). Host-owned exclusions (OAuth flows,
token issuance, session/transport security, sandbox execution, memory-store
implementation, and model behavior) are declared explicitly so that no claim
overreaches SigilGuard's boundary as an embedded library.

## Research Question

Against the current agentic and MCP attack landscape, which threats does an
embedded SigilGuard verifier mitigate, which does it only detect, and which are
structurally out of scope for a library that does not own the transport,
identity provider, sandbox, or model? Each answer MUST be tied to a named
control and a named test family so that a lesser implementor can build the M5
suite without judgment calls.

## Methodology

Sources are primary where a primary source exists: the OWASP Agentic Top 10
2026, the MCP specification and its security best-practices guide, the Trail of
Bits line-jumping disclosure, the MCPTox paper, the CaMeL paper, the
"Design Patterns for Securing LLM Agents against Prompt Injections" paper,
Simon Willison's lethal-trifecta essay, the ETDI paper, CSA MCP material, the
public CVE records, and vendor incident writeups for the postmark-mcp and
Smithery compromises. Attack claims were cross-checked against the SigilGuard
codebase contracts (`SigilGuard.Context` boundary vocabulary, the runtime gate,
the MCP gateway, the scanner pipeline, the confirmation tokens, and the audit
chain) so that each control names a real module or mechanism.

Two claims required a claim-level judgment and are recorded here so downstream
specs inherit the corrected figure:

- **CaMeL utility:** the paper reports solving **77% of AgentDojo tasks with
  provable security** (versus 84% for an undefended agent), not ~100% task
  utility. The near-total figure secondary coverage cites is the *security*
  result (injection defeated by construction), not the *utility* result. This
  note uses "77% utility with provable, near-total injection defense."
- **MemoryGraft magnitude:** the paper's abstract supports "a small number of
  poisoned records account for a large fraction of retrieved experiences" and up
  to **~48% poisoned recall** via union lexical+embedding retrieval. A widely
  quoted "87% downstream corruption" figure appears in secondary coverage and
  could not be re-verified against the paper on 2026-07-02; this note uses the
  verifiable ~48% poisoned-recall figure and cites the paper directly.

## Context

SigilGuard is an embedded, native-Elixir security runtime for MCP and
agent-tool boundaries. It ships no proxy, no control plane, and no model. Its
boundary vocabulary already models phase, origin, source, sink, actor,
identity, trust zone, action, and audience (`SigilGuard.Context`). That
vocabulary is exactly what the current attack landscape demands: mid-2026
attacks are overwhelmingly boundary attacks, not payload-only attacks. A scanner
that only inspects tool *output* misses tool poisoning, line jumping, and schema
injection, because those live in tool *metadata* delivered before any content is
scanned. SigilGuard's answer is a verification ladder over signed trust
material, not a single filter.

This note feeds the threat sections of SP.03 (manifest gateway), SP.04 (boundary
policy kernel), and SP.13 (agent-to-agent trust), the M5 threat suite, and the
published threat-model guide (SP.14). It ratifies the v3 scope additions that
the mapping depends on: `agent_request` / `agent_response` statement types,
deepened sandbox identity (`sandbox_id` inside the context digest), and
sink-aware output contracts.

## Findings

### OWASP Top 10 For Agentic Applications 2026 (ASI01-ASI10)

The 2026 list reframes LLM risk around autonomous, tool-using agents. The ten
classes are the spine of the mapping table:

- **ASI01 Agent Goal Hijack** - untrusted content redirects the agent's plan.
- **ASI02 Tool Misuse & Exploitation** - the agent is steered into invoking
  tools abusively, or tool metadata itself is weaponized.
- **ASI03 Agent Identity & Privilege Abuse** - confused-deputy, token
  passthrough, and delegation-scope abuse.
- **ASI04 Agentic Supply Chain Compromise** - poisoned tools, bundles,
  packages, and hosting infrastructure.
- **ASI05 Unexpected Code Execution** - agent or tool output reaches an
  execution sink.
- **ASI06 Memory & Context Poisoning** - persisted memory or retrieved context
  corrupts future behavior.
- **ASI07 Insecure Inter-Agent Communication** - unauthenticated or
  unverifiable A2A messages.
- **ASI08 Cascading Agent Failures** - one compromise propagates across an
  agent graph.
- **ASI09 Human-Agent Trust Exploitation** - the agent manipulates a human
  approver, or a spoofed approval manipulates the agent.
- **ASI10 Rogue Agents** - an agent operates outside its authorized envelope.

### Named MCP Attack Taxonomy (mid-2026)

The MCP-specific taxonomy is concrete and mostly pre-invocation, which is why
metadata verification precedes content scanning in SigilGuard:

- **Tool poisoning via descriptions/metadata (MCPTox).** Malicious instructions
  hide in tool descriptions and schemas. MCPTox evaluated 45 live servers, 353
  authentic tools, and 1,312 malicious cases across 20 agents, reaching attack
  success rates up to 72.8% (o1-mini); routing an attack through MCP raised
  success by 7-15 percentage points over the non-MCP baseline.
- **Line jumping (Trail of Bits, 2025-04-21).** A server injects behavior-
  altering text through `tools/list` descriptions, so the model is compromised
  *before any tool is invoked*, bypassing invocation-time controls entirely.
- **Schema injection.** A server adds an adversarial required parameter such as
  `AWS_ACCESS_KEY_ID`; the agent treats the requirement as a legitimate API
  constraint and fills it from environment or system prompt. Output scanners
  cannot see this because the manipulation is in the schema, not the result.
- **Rug pull / TOFU drift.** A tool is benign at trust-on-first-use, then swaps
  its definition after approval (also the pattern behind CVE-2025-54136).
- **Confused deputy incl. consent-cookie replay.** A proxy with static client
  credentials is tricked into replaying a stored consent to a new audience.
- **Token passthrough.** A server forwards a client token to an upstream API it
  was not issued for; the MCP spec explicitly forbids this.
- **Stale authorization across request/list changes.** Earlier MCP revisions
  exposed resumable-session attacks. MCP `2026-07-28` removes protocol
  sessions and delivers list changes through subscriptions, but a host can
  still reuse stale authorization or approvals after a changed listing.
- **Memory poisoning (MemoryGraft).** Grafted "successful experiences" persist
  in long-term memory and re-surface via lexical+embedding retrieval (up to
  ~48% poisoned recall), inducing behavioral drift until the store is rebuilt.
- **Prompt injection via tool results.** Untrusted result content carries
  instructions; documented variants include GitHub PR-title hijacks that steer
  coding agents.
- **Supply-chain compromise.** The postmark-mcp npm package built trust over 15
  versions, then added a one-line BCC backdoor in v1.0.16 (1,643 downloads
  before removal). The Smithery hosting path-traversal (`dockerBuildPath`)
  exposed 3,000+ hosted servers and their credentials.
- **Ecosystem tooling RCE.** CVE-2025-49596 (MCP Inspector RCE, CVSS 9.4),
  CVE-2025-6514 (mcp-remote command injection, CVSS 9.6), and CVE-2025-54136
  (Cursor "MCPoison" config-swap persistence) are vulnerabilities in *tooling*,
  not in any SigilGuard-controlled surface.
- **A2A impersonation and delegation abuse.** A peer agent spoofs an identity or
  escalates a delegated scope beyond its grant.
- **Lethal trifecta (Willison).** Any agent that simultaneously has private-data
  access, exposure to untrusted content, and an external-communication sink can
  be driven to exfiltrate data with no code vulnerability at all.

Surrounding context matters: an internet scan found 1,862 exposed MCP servers,
and a 119-server sample allowed unauthenticated tool listing on all 119. CSA
guidance is therefore to treat every MCP server as an untrusted third party and
enforce zero trust at the tool layer. SigilGuard's posture follows directly:
**assume the tooling is compromised and verify at the boundary.**

### Why A Deterministic Policy Kernel, Not Model Guardrails Alone

Model-level guardrails are probabilistic classifiers over text. They help, but
they cannot offer a proof, they degrade under distribution shift, and they are
the very surface prompt injection targets. The research consensus is that
security must be *structural*:

- **CaMeL** ("Defeating Prompt Injections by Design", arXiv 2503.18813)
  extracts control and data flow from the trusted query so untrusted data can
  never alter program flow, and enforces capabilities when tools are called. It
  solves 77% of AgentDojo tasks with provable security (versus 84% undefended),
  demonstrating that a deterministic policy layer around the model defeats
  injection by construction at modest utility cost.
- **"Design Patterns for Securing LLM Agents against Prompt Injections"**
  (arXiv 2506.08837) catalogues six patterns - action-selector,
  plan-then-execute, map-reduce, dual-LLM, code-then-execute, and
  context-minimization - whose shared principle is that untrusted content must
  never reach a privileged action without passing a deterministic checkpoint.
- **Willison's lethal trifecta** reduces the failure condition to three
  simultaneous data-flow properties, which is a policy statement, not a
  classifier: block or gate the action when all three hold.

SigilGuard's boundary/trust-zone policy kernel is the embedded, deterministic
realization of these patterns. The `SigilGuard.Context` fields
(phase, origin, source, sink, trust_zone, actor, action, audience) are exactly
the labels a plan-then-execute or dual-LLM design needs to make a fail-closed
decision without consulting the model.

**Worked lethal-trifecta policy sketch.** The kernel treats the trifecta as a
conjunction over context labels and resolves it deterministically:

```text
rule "lethal-trifecta-exfiltration"
  when   source.sensitivity == :private          # private-data source
   and    origin in [:tool, :resource, :repo]     # untrusted content origin
   and    trust_zone == :untrusted
   and    sink in [:external, :network]           # external-comms sink
  then   :block                                    # default: fail closed
   else_if actor.trust_level == :high
          and human_confirmation_present?
  then   :confirm                                  # explicit, digest-bound
```

The decision is reproducible, auditable, and independent of model cooperation.
The confirmation branch binds to an exact action digest (including `sandbox_id`)
so a human approval cannot be replayed against a different action. This is the
policy-kernel answer to ASI01, ASI02, ASI05, and ASI06 simultaneously.

### Mitigation Placement: Where SigilGuard Sits

The defensive ecosystem is fragmented across four placements, none of which is
an embedded Elixir library that combines signed bundles, canonical
attestations, deterministic policy, and tamper-evident audit:

- **Proxy / gateway** - IBM ContextForge, Lasso, the Windows 11 MCP proxy, and
  Pipelock mediate traffic out-of-process. They see the wire but add a sidecar,
  a network hop, and a second trust domain, and their evidence is external to
  the host.
- **Model guardrails** - LlamaFirewall / PromptGuard 2 and NeMo Guardrails
  classify text probabilistically. Useful signal, no proof, and injection-
  facing.
- **Scanners** - mcp-scan, MCPGuard, and similar tools audit servers or
  descriptions, typically as a scan-time or CI step, not an in-process runtime
  verdict.
- **Embedded library** - runs in the host process, returns a synchronous
  verdict, and emits signed evidence with no sidecar. This is SigilGuard's
  niche.

The closest research analog is **ETDI** (arXiv 2506.01333), which adds
OAuth-enhanced, immutably versioned, signed tool definitions with policy-based
access control to counter tool squatting and rug pulls. ETDI validates the
signed-definition direction; SigilGuard generalizes it to an offline,
transport-agnostic profile with canonical attestations and audit proofs. CSA's
zero-trust-at-the-tool-layer guidance and the 1,862-unauthenticated-server scan
are the market evidence that this layer is missing and needed.

## Control Mapping

This is the normative artifact. One row per attack. `Control` names the module
or mechanism and its owning spec. `Claim` is one of `mitigates`, `detects`, or
`out-of-scope` (definitions below). `Test` is the M5 family that MUST be green
before 1.0.0.

| # | Attack | ASI class | SigilGuard control (module / mechanism, spec) | Claim | Test |
|---|--------|-----------|-----------------------------------------------|-------|------|
| 1 | Prompt injection via tool results (incl. GitHub PR-title hijack) | ASI01 | Result-phase scanner pipeline + streaming holdback + sink-aware output contract; boundary policy kernel taints `tool_result` origin (SP.04) | mitigates | TM.01 |
| 2 | Tool poisoning via descriptions/metadata (MCPTox) | ASI02, ASI04 | Capability-manifest digest pinning over description+schema+annotation digests; drift rejection (SP.03) | mitigates | TM.02 |
| 3 | Line jumping (pre-invocation, via `tools/list`) | ASI01, ASI02 | Manifest-time verification: `tools/list` output is verified against pinned manifest digests before any content enters model context (SP.03) | mitigates | TM.03 |
| 4 | Schema injection (adversarial required params, e.g. `AWS_ACCESS_KEY_ID`) | ASI02, ASI03 | Input-schema digest binding + schema validation; adversarial-required-param indicators bound into the manifest digest (SP.03) | mitigates + detects | TM.04 |
| 5 | Rug pull / TOFU drift | ASI04 | Digest-pinned manifest with drift rejection; `notifications/tools/list_changed` drops cached approvals and forces re-verification (SP.03) | mitigates | TM.05 |
| 6 | Confused deputy incl. consent-cookie replay | ASI03 | Attestation binds audience + resource + actor; nonce/replay scope on ReplayStore; DSSE expiry (SP.01, SP.03) | mitigates (partial) | TM.06 |
| 7 | Token passthrough (spec-forbidden) | ASI03 | Gateway deny rule: audience/resource mismatch is an explicit block; attestation records the intended audience (SP.03) | mitigates | TM.07 |
| 8 | Stale authorization across stateless requests and list-change delivery | ASI03, ASI02 | Each request is independently gated; changed listings invalidate cached approvals; per-action nonce and replay scope avoid connection authority (SP.03, SP.16) | detects (partial) | TM.07 |
| 9 | Memory & context poisoning (MemoryGraft) | ASI06 | Model-ingress gating: retrieved memory/context crosses `tool_result`->`outbound_model` through the scanner + trust-zone policy before reaching the model; digest provenance on ingested records (SP.04) | mitigates + detects | TM.08 |
| 10 | Lethal trifecta dataflow (private data + untrusted content + external comms) | ASI01, ASI02, ASI05 | Boundary policy kernel dataflow rule (source sensitivity x untrusted origin x external sink => block/confirm); sink-aware output contracts (SP.04) | mitigates | TM.09 |
| 11 | Unexpected code execution via tool/agent output | ASI05 | Sink-aware output contract denies untrusted-origin content into exec/command sinks; confirmation bound to action digest incl. `sandbox_id` (SP.04, SP.03) | mitigates (dataflow); out-of-scope (the runtime that executes) | TM.09 |
| 12 | A2A impersonation | ASI07, ASI10 | Agent-card verification against trust-bundle issuers; unknown-agent quarantine default (SP.13) | mitigates | TM.10 |
| 13 | A2A delegation abuse | ASI03, ASI07 | Delegation-chain validation: act-claim nesting, max depth, trust derivation across hops (SP.13) | mitigates | TM.10 |
| 14 | Supply-chain: backdoored package (postmark-mcp BCC backdoor) | ASI04 | Manifest/bundle digest drift detection on the changed version; egress dataflow policy flags the hidden external sink (SP.02, SP.04) | detects (partial) | TM.11 |
| 15 | Supply-chain: hosting-infra path traversal (Smithery) | ASI04 | Trust-bundle verification + quarantine if a redistributed bundle/manifest fails signature or drifts from pinned digests (SP.02) | out-of-scope (infra); detects drift | TM.11 |
| 16 | Ecosystem tooling RCE - CVE-2025-49596 (MCP Inspector, CVSS 9.4) | ASI05 | None; justifies the assume-compromised-tooling posture. Audit chain records the boundary decisions around the affected tool (SP.05) | out-of-scope | TM.11 |
| 17 | Ecosystem tooling RCE - CVE-2025-6514 (mcp-remote, CVSS 9.6) | ASI05 | None; the vulnerable client is host-owned transport tooling. Assume-compromised posture applies (SP.05) | out-of-scope | TM.11 |
| 18 | Config-swap persistence - CVE-2025-54136 (Cursor "MCPoison") | ASI04, ASI05 | Not patchable in Cursor; SigilGuard's analogous defense is digest-pinned re-approval - any manifest/config change forces new confirmation (SP.03) | out-of-scope (the IDE); mitigates the analogous pattern | TM.05 |
| 19 | Cascading agent failures | ASI08 | Per-hop attestation + delegation-chain evidence lets an operator reconstruct the propagation path; no automatic containment (SP.13, SP.05) | partial (evidence-only) | TM.12 |
| 20 | Rogue agents operating outside envelope | ASI10 | Agent-card + delegation-chain verification denies unknown/unbundled agents at the boundary; audit flags out-of-envelope actions (SP.13) | detects-at-boundary | TM.10 |
| 21 | Human-agent trust exploitation (spoofed/forged approval) | ASI09 | Confirmation tokens bound to exact action digest incl. `sandbox_id`; single-use + TTL defeats replayed/forged approvals (SP.03, SP.08) | mitigates (the token); out-of-scope (human judgment) | TM.06 |
| 22 | Repudiation / audit tamper & truncation | ASI08, ASI03 | Audit HMAC chain + Merkle checkpoints + inclusion/consistency proofs + external anchors; truncation is detectable via consistency proof (SP.05) | mitigates + detects | TM.12 |

The table has **22 rows**: 12 `mitigates` (some jointly `detects`), 3
`detects`/`partial`, and 7 `out-of-scope` or evidence-only, several of which
still carry an analogous or drift-detection control.

## Control Inventory

This reverse index lists each SigilGuard control once, names its owning spec,
and points to the rows it serves. It exists so an implementor can see the full
attack coverage of a single control and size its tests accordingly.

| Control (mechanism) | Spec | Serves rows |
|---------------------|------|-------------|
| Capability-manifest digest pinning + drift rejection | SP.03 | 2, 4, 5, 18 |
| Manifest-time `tools/list` verification (line-jump defense) | SP.03 | 3, 5 |
| Trust-bundle verification / quarantine / revocation | SP.02 | 14, 15 |
| Typed DSSE attestations + replay/nonce/expiry | SP.01 | 6, 8 |
| Confirmation tokens bound to action digest incl. `sandbox_id` | SP.03, SP.08 | 11, 21 |
| Boundary policy kernel: source/sink/trust-zone dataflow | SP.04 | 1, 9, 10, 11 |
| Sink-aware output contracts | SP.04 | 1, 10, 11, 14 |
| Untrusted/absent-sandbox -> quarantine default | SP.04 | 11 |
| Scanner pipeline + streaming holdback | SP.04 | 1, 9 |
| Gateway audience/resource deny (token passthrough) | SP.03 | 7, 8 |
| Agent-card verification + delegation-chain validation | SP.13 | 12, 13, 19, 20 |
| Audit HMAC chain + Merkle checkpoints + inclusion/consistency proofs + anchors | SP.05 | 16, 17, 19, 22 |

The audit chain appears against the `out-of-scope` CVE rows because, while
SigilGuard cannot patch ecosystem tooling, it MUST still record the boundary
decisions taken around a compromised tool so an incident is reconstructable.

## Claim-Level Definitions

These definitions are normative for every row above and for the M5 suite.

- **mitigates** - SigilGuard prevents the attack from producing its intended
  effect at the boundary it controls, deterministically and without model
  cooperation. A `mitigates` row MUST have a test that asserts the malicious
  input is blocked, quarantined, or forced through confirmation.
- **detects** - SigilGuard cannot prevent the root cause (it lives in a
  host-owned surface) but produces a deterministic, tamper-evident signal:
  digest drift, quarantine indicator, replay rejection, or an audit record. A
  `detects` row MUST have a test that asserts the signal fires.
- **partial** - the control covers one facet (for example, replay or drift) but
  a co-located host-owned surface (OAuth consent, transport session) is required
  for full coverage. The partial boundary MUST be named in the row and in the
  exclusions section.
- **out-of-scope** - the vulnerability lives entirely in a surface SigilGuard
  does not own (ecosystem tooling, IDE, transport client). SigilGuard cannot
  patch it; its role is to justify the assume-compromised posture and to record
  evidence. `out-of-scope` rows MUST NOT claim prevention.

## Host-Owned Exclusions

SigilGuard is a library. The following surfaces are the host application's
responsibility, and no control row may claim to secure them:

- **OAuth flows and token issuance.** SigilGuard consumes an already-issued
  identity/audience and binds it into attestations; it does not run the
  authorization server, mint tokens, or manage consent cookies.
- **Transport and subscription security.** TLS, subscription delivery, and
  request routing belong to the host transport. MCP `2026-07-28` removes
  protocol sessions; SigilGuard adds per-action nonce/replay and manifest-list
  invalidation as assists only.
- **Sandbox execution itself.** SigilGuard requires `sandbox_id` and isolation
  level as attested inputs and defaults untrusted/absent sandboxes to
  quarantine, but it does not create, run, or escape-harden the sandbox.
- **Memory-store implementations.** SigilGuard gates content at the model-
  ingress boundary and can bind provenance digests, but the vector store, RAG
  index, and eviction policy are host-owned.
- **Model behavior.** SigilGuard is deterministic by design and never relies on
  the model to refuse an attack; model alignment and refusal are out of scope.

## Test Families

Each family becomes a module under `test/sigil_guard/threat_model/`. Every
`mitigates` and `detects` row MUST map to a green module before 1.0.0 (M5).
Each module MUST include negative, tamper, replay, expiration, and malformed-
input cases per repository rule 9, and MUST cite the sourced attack it defends.

| ID | Family | Primary rows |
|----|--------|--------------|
| TM.01 | Prompt injection via tool results | 1 |
| TM.02 | Tool poisoning (descriptions/metadata) | 2 |
| TM.03 | Line jumping (pre-invocation manifest verification) | 3 |
| TM.04 | Schema injection | 4 |
| TM.05 | Rug pull / TOFU drift | 5, 18 |
| TM.06 | Confused deputy + consent replay | 6, 21 |
| TM.07 | Token passthrough + stale stateless authorization | 7, 8 |
| TM.08 | Memory poisoning (model-ingress gating) | 9 |
| TM.09 | Lethal-trifecta dataflow | 10, 11 |
| TM.10 | A2A impersonation / delegation abuse | 12, 13, 20 |
| TM.11 | Supply chain (tampered/revoked bundle) | 14, 15, 16, 17 |
| TM.12 | Repudiation / audit tamper & truncation | 19, 22 |

## Comparative Analysis

The comparison is mitigation placement: what each option can and cannot do
against the taxonomy above.

| Criterion | Proxy / gateway | Model guardrails | Scanners | Embedded library (SigilGuard) |
|-----------|-----------------|------------------|----------|-------------------------------|
| Security | Wire-level mediation; second trust domain | Probabilistic; injection-facing | Point-in-time audit | Deterministic in-process verdict + signed bundles |
| Determinism | Partial | No | Partial | Yes, fail-closed |
| Evidence | External receipts | None standard | Report artifacts | Tamper-evident audit chain + proofs |
| Operational fit | Sidecar + network hop | Extra model call | CI/scan step | No sidecar; OTP-supervised in host |
| Pre-invocation cover | Limited | No | Yes (scan-time) | Yes (manifest digest + line-jump verify) |
| Niche gap it leaves | Not embedded | No proof | Not runtime verdict | None - fills the missing layer |

No mature embedded library combines signed trust bundles, canonical
attestations, deterministic boundary policy, and tamper-evident audit. That
combination is SigilGuard's niche, with ETDI as the closest signed-definition
research analog and CSA zero-trust guidance as the market rationale.

## Recommendation

**Decision:** adopted.

This threat model is the normative control-mapping source for SigilGuard v3.
Every row marked `mitigates` or `detects` MUST have a green test module under
`test/sigil_guard/threat_model/` before the 1.0.0 release (milestone M5). The
model also ratifies the v3 scope additions the mapping depends on:
`agent_request` / `agent_response` statement types (D7), deepened sandbox
identity (`sandbox_id` inside the context digest), and sink-aware output
contracts (D8). `out-of-scope` rows MUST NOT be softened into prevention claims;
they exist to justify the assume-compromised-tooling posture and to bound
SigilGuard's honest security surface.

**Rationale:** the mid-2026 landscape is dominated by boundary attacks that
model-level filtering cannot stop by construction. A deterministic policy kernel
over signed trust material - validated in direction by CaMeL, the design-
patterns catalogue, and ETDI - is the only defense that offers reproducible,
auditable verdicts inside the host process. Naming a claim level and a test
family per attack converts the research into an enforceable acceptance gate.

## Impact On SigilGuard

- **Modules affected:** `SigilGuard.Context`, the runtime gate and
  `BoundaryPolicy`, the scanner pipeline, the MCP/capability manifest gateway,
  the confirmation tokens, the trust-bundle verifier, the audit chain, and the
  future `SigilGuard.AgentCard`.
- **Specs to create/update:** feeds the threat sections of SP.03 (manifest
  gateway), SP.04 (boundary policy kernel + output contracts + lethal-trifecta
  rule), and SP.13 (agent-to-agent trust); ratified by SP.14 as the source for
  the published threat-model guide.
- **Migration needed:** none directly; the model governs new v3 test and
  documentation surfaces rather than changing consumer contracts.
- **Breaking changes:** none introduced by this note; it depends on the v3 scope
  additions (agent statements, sandbox identity, output contracts) rather than
  creating new breaks.

## Sources

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
- [OWASP MCP Tool Poisoning](https://owasp.org/www-community/attacks/MCP_Tool_Poisoning)
- [Trail of Bits - Jumping the line: How MCP servers can attack you before you ever use them (2025-04-21)](https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/)
- [MCPTox: Tool Misuse and Toxicity in MCP Agents (arXiv 2508.14925)](https://arxiv.org/abs/2508.14925)
- [MCP Schema Injection - Stealing AI Agent Credentials (accessed 2026-07-02)](https://deconvoluteai.com/blog/mcp-schema-injection-attack)
- [CaMeL - Defeating Prompt Injections by Design (arXiv 2503.18813)](https://arxiv.org/abs/2503.18813)
- [Design Patterns for Securing LLM Agents against Prompt Injections (arXiv 2506.08837)](https://arxiv.org/abs/2506.08837)
- [Simon Willison - The lethal trifecta for AI agents (2025-06-16)](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)
- [ETDI: Mitigating Tool Squatting and Rug Pull Attacks in MCP (arXiv 2506.01333)](https://arxiv.org/abs/2506.01333)
- [MemoryGraft: Persistent Compromise of LLM Agents via Poisoned Experience Retrieval (arXiv 2512.16962; 87% downstream figure from secondary coverage unverified, accessed 2026-07-02)](https://arxiv.org/abs/2512.16962)
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [CSA Agentic MCP Security Best Practices](https://labs.cloudsecurityalliance.org/agentic/agentic-mcp-security-best-practices-v1/)
- [Knostic - 1,862 exposed MCP servers lack essential security (accessed 2026-07-02)](https://www.knostic.ai/blog/mapping-mcp-servers-study)
- [Snyk - Malicious MCP Server on npm postmark-mcp Harvests Emails (accessed 2026-07-02)](https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/)
- [GitGuardian - From Path Traversal to Supply Chain Compromise: Breaking MCP Server Hosting (Smithery, accessed 2026-07-02)](https://blog.gitguardian.com/breaking-mcp-server-hosting/)
- [CVE-2025-49596 - Anthropic MCP Inspector RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2025-49596)
- [CVE-2025-6514 - mcp-remote OS command injection (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2025-6514)
- [CVE-2025-54136 - Cursor MCPoison config-swap persistence (Check Point Research, accessed 2026-07-02)](https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/)
