---
sigil_guard:
  id: "R.01"
  topic: "Embedded Agent Trust Profile"
  category: research
  status: complete
  created: "2026-07-01"
  updated: "2026-07-02"
  decision: adopted
  tags:
    [
      "mcp",
      "agent-trust",
      "trust-bundles",
      "attestation",
      "supply-chain",
      "audit"
    ]
---

# R.01 - Embedded Agent Trust Profile

## Executive Summary

SigilGuard should not try to revive or depend on the discontinued upstream
protocol and hosted registry model. The durable direction is a SigilGuard Agent
Trust Profile: an embedded, local-first trust layer for agent and tool
boundaries that composes with MCP, A2A, ACP, OAuth, OpenTelemetry,
CloudEvents, TUF, SCITT, SLSA, in-toto/DSSE, DIDs, and Verifiable Credentials
without becoming a web registry or SaaS control plane.

The profile should aim higher than compatibility. It should be a small,
implementation-oriented profile that can become a de facto standard for
verifiable agent-tool calls: signed local trust bundles, typed capability
manifests, canonical request/result attestations, deterministic boundary policy,
source-to-sink scanning, confirmation tokens bound to exact action digests,
quarantine for suspicious outputs and bundles, and privacy-preserving audit
evidence that can be exported or externally anchored.

The historical SIGIL surface is not a runtime migration layer for v3. It is
historical context and migration-documentation input. Existing `_sigil` fields,
confirmation metadata, envelope fixtures, profile names, and registry-named
modules should be mapped to v3 Agent Trust replacements in changelog and
`MIGRATING-1.0.md`, not preserved as permanent compatibility shims.

## Research Question

What profile should SigilGuard define for embedded MCP and broader agent-tool
security if the original upstream protocol and hosted registry are no longer
dependable runtime substrates?

The profile must satisfy six constraints:

1. It must work offline inside an Elixir host application.
2. It must compose with MCP today and with A2A/ACP-style agent protocols without
   becoming a competing transport.
3. It must bind identity, tool capability, action intent, payloads, resources,
   policy decisions, and evidence into typed canonical bytes.
4. It must prevent old-registry assumptions from re-entering the runtime path.
5. It must define the v3 breaking boundary clearly enough that migration is
   mechanical for existing users.
6. It must be testable with golden vectors, tamper cases, replay cases, and
   offline verification.

## Methodology

This review used four evidence streams:

- **Primary standards and specifications:** MCP authorization and security
  material, OAuth protected-resource and resource-indicator RFCs, HTTP Message
  Signatures, JSON Canonicalization Scheme, CloudEvents, OpenTelemetry GenAI
  semantic-convention work, W3C DID/VC specifications, TUF, SCITT, SLSA,
  in-toto, DSSE, and Sigstore bundle material.
- **Academic and standards-adjacent security literature:** agentic prompt
  injection, MCP tool poisoning, MCP threat modeling, capability attestation,
  supply-chain provenance, transparency logs, and AI risk-management profiles.
- **Current SigilGuard codebase contracts:** pure-Elixir backend selection,
  historical envelope fixtures, registry-named foundation modules, staged
  scanning, MCP gateway helpers, confirmation tokens, audit exports, repo
  policy, release provenance, and quality-gate constraints.
- **Local adjacent ecosystem review:** private notes and code patterns from
  nearby agent-runtime work were used to extract convergent architecture
  patterns. Project-specific names are deliberately excluded from this research
  note; only generalized, standards-cross-checked patterns are carried forward.

The analysis favored patterns with broad standard alignment, deterministic
offline verification, minimal dependency footprint, and clear Elixir module
boundaries. Hosted registry and SaaS control-plane designs were rejected as the
default architecture because SigilGuard is an embeddable library.

## Context

The current codebase has a strong pure-Elixir foundation: envelope
signing, replay checks, MCP gateway helpers, streaming sanitization,
confirmation tokens, staged scanning, signed bundle verification/quarantine,
audit checkpoints/exports, release SBOM tasks, repo policy, and coverage above
95%. The remaining strategic gap is not "finish the port." It is defining a
modern trust architecture that is boundary-aware enough for agent systems and
small enough to embed cleanly.

MCP is becoming the dominant tool boundary, while A2A and ACP-style protocols
are converging on inter-agent and editor-agent interoperability. Those protocols
standardize communication, discovery, and integration shape. They do not by
themselves provide a complete local trust profile for signed tool manifests,
replay-safe action attestations, output quarantine, deterministic policy,
privacy-preserving audit records, and release/bundle provenance. That is the
space SigilGuard should occupy.

## Package Adoption And Breaking-Change Tolerance

Hex evidence supports a v3 breaking refactor instead of long-term legacy
compatibility. On July 1, 2026, the public Hex package API showed `sigil_guard`
at version `0.2.0`, with about 180 all-time downloads, 9 downloads in the prior
week, 6 downloads in the prior day, and no visible reverse dependencies. The
published package metadata still described the library as upstream-protocol
integration with optional Rust/NIF pieces, which no longer matches the intended
repo direction.

That means the main migration risk is private/direct Git use, not broad public
Hex adoption. V3 should therefore be explicit and honest:

- keep package users on `~> 0.2` unless they opt into `~> 1.0`;
- align the repo directly to `1.0.0` as the major release line;
- document every removed public API in `MIGRATING-1.0.md`;
- avoid carrying abandoned protocol vocabulary as runtime architecture.

## Standards Landscape

### Agent Protocols Are Transports, Not Complete Trust Models

MCP defines a practical tool boundary. Its authorization specification now
anchors HTTP transports in OAuth resource-server concepts: protected-resource
metadata, authorization-server discovery, scopes, and resource indicators. That
gives SigilGuard a concrete binding target: actor, token audience, MCP server
URI, tool name, scopes, resource, and transport context.

A2A and ACP address adjacent protocol seams: cross-agent communication and
editor-agent communication. They reinforce the same strategic conclusion:
SigilGuard should not invent a new agent transport. It should provide a trust
profile that can be attached to MCP tool calls, A2A messages, ACP sessions, local
stdio tools, and host-internal tool runners.

### Identity Should Be Verifiable But Registry-Optional

OAuth supplies online authorization context for HTTP MCP deployments. DIDs and
Verifiable Credentials supply a registry-independent vocabulary for signed
claims when a host wants portable identity. SigilGuard should not require DID or
VC infrastructure in the default path, but its profile should be compatible with
those shapes:

- `actor` can be a local principal, DID, service account, or host-provided
  subject.
- `issuer` can be a local root key, organization key, CI key, or trusted bundle
  signer.
- `credential_refs` can point to optional VC-style evidence without forcing a
  universal identity registry.
- `audience` and `resource` must be explicit for every networked call.

This keeps identity verifiable without replacing the host application's auth
system.

### Supply-Chain Standards Fit Tool Manifests Better Than Registries

Tool definitions are supply-chain inputs. Tool names, descriptions, schemas,
annotations, side-effect classifications, sandbox requirements, and output
contracts all influence model behavior and policy decisions. The right prior art
is therefore not a live public registry; it is signed metadata and provenance:

- TUF contributes local root trust, role separation, threshold signatures,
  expiry, rollback protection, and freeze-attack handling.
- in-toto and DSSE contribute typed statements and signatures over payloads with
  explicit predicate types.
- SLSA contributes provenance fields that separate trusted platform metadata
  from untrusted external parameters.
- Sigstore bundle and SCITT work contribute portable verification material,
  transparency receipts, and non-centralized auditability.

SigilGuard should adopt these patterns at library scale. It does not need to
become an updater or transparency service; it needs signed bundle verification,
monotonic sequence checks, expiry, revocation, quarantine, and optional
transparency/export hooks.

### Canonical Attestations Need Type And Boundary Binding

The core attestation requirement is not "sign a JSON object." It is "sign a
typed, canonical statement whose subject, payload type, tool manifest digest,
action digest, payload digest, context digest, audience/resource, policy verdict,
nonce, expiry, and issuer key id are unambiguous inside the signed bytes."

RFC 8785/JCS is the likely long-term canonicalization target for JSON
interoperability. DSSE-style envelopes are the likely long-term shape for
detached payload signatures. HTTP Message Signatures are relevant at the HTTP
transport boundary, but they are not enough for local stdio tools or persisted
audit evidence. SigilGuard should define canonical internal vectors first and
leave room for JCS/DSSE-compatible encodings as the profile matures.

### Observability Should Be Evidence-Oriented

OpenTelemetry GenAI semantic conventions and CloudEvents point to a portable
event vocabulary, but they are observability formats, not trust decisions. The
SigilGuard profile should emit OTel-compatible attributes and CloudEvents-shaped
exports while keeping sensitive payloads out of default telemetry. Audit evidence
should be digest-first and correlation-rich:

- decision id, trace id, span id, actor, tenant/scope when supplied;
- tool manifest digest and sandbox identity;
- source, sink, trust zone, and phase;
- action, payload, and context digests;
- verdict, policy rule ids, scanner stages, and quarantine references;
- checkpoint, Merkle root, export, and external-anchor references.

### Agentic Risk Guidance Is System-Level

OWASP Agentic AI material, CSA MCP guidance, NIST AI RMF material, and recent
MCP security papers converge on the same point: prompt injection and tool
poisoning are not filter-only problems. They require architectural controls:
least privilege, capability attestation, sandboxing, boundary controls,
approval workflows, telemetry, supply-chain validation, and incident evidence.

SigilGuard should therefore treat scanning as one stage in a broader pipeline,
not as the product. Regex and deterministic scanners remain useful, but the
profile must bind where data came from, where it is going, what tool can do, who
authorized it, what policy matched, and what evidence was emitted.

## Adjacent Ecosystem Pattern Review

The local adjacent ecosystem review produced six reusable patterns. Names and
product-specific details are intentionally omitted; each pattern is retained only
where it matches independent standards or research findings.

### Model-Neutral Trust Substrate

The durable platform layer is not the model and not the editor. It is the
governance, verification, traceability, and policy layer above heterogeneous
models and tools. SigilGuard fits this as a Hex library: small public behaviours,
deterministic defaults, optional lifts, no hard dependency on a model provider,
and no hosted control plane.

### Policy-As-File And Typed Steering Material

Agent systems are converging on project-local instruction, policy, and tool
definition files. SigilGuard should treat these as signed or hash-bound inputs,
not informal comments. This maps directly to trust bundles, repo policy,
capability manifests, and bundle provenance.

### Customer-Controlled Execution Boundary

Modern agent deployments split orchestration from tool execution. Tools may run
locally, in a host application, in a tenant-controlled sandbox, or behind an MCP
server. SigilGuard should not own the sandbox, but it should require sandbox
identity and isolation level to be part of capability manifests and runtime
attestations.

### Durable Event History

Long-running agent actions need checkpoint, replay, cancellation, and
post-incident reconstruction. SigilGuard should record decision evidence in a
format that can be correlated with host traces and exported to audit storage
without leaking raw payloads.

### Verification Ladder Over Single Gate

Security decisions should be staged: static bundle validation, capability drift
checks, policy evaluation, scanner pipeline, confirmation gate, runtime
attestation, output quarantine, and audit anchoring. This is stronger than a
single regex scanner or a single allowlist.

### Adaptive Layer Over Deterministic Baseline

The core profile must work with deterministic Elixir code only. ML classifiers,
embedding-based anomaly detection, or external red-team evaluators may be useful
later, but they should be optional lifts over deterministic baseline stages.

## Candidate Profile: SigilGuard Agent Trust Profile

The candidate standard surface is the **SigilGuard Agent Trust Profile**. It is
not a new network registry and not a replacement for MCP/A2A/ACP. It is a
portable evidence and policy profile that an embedded verifier can apply to any
agent-tool boundary.

### Layer 1: Trust Bundle

Trust bundles are local signed artifacts shipped with the host application,
loaded from release files, mounted from configuration, or provided explicitly by
the caller. A bundle contains:

- profile version and bundle sequence number;
- root and delegated signing keys;
- tool capability manifests;
- policy rules and trust-zone definitions;
- scanner pattern sets and staged-pipeline configuration;
- identity issuers and optional credential references;
- revocations, expiry, and rollback floor;
- provenance and optional transparency/export references.

Verification is offline by default. Remote fetch is not part of the core
profile. Hosts that want remote bundle distribution own the transport and pass
verified bytes or local bundle files into SigilGuard.

### Layer 2: Capability Manifest

Every tool needs a signed or bundle-bound manifest. The manifest must be treated
as part of the trust boundary because tool metadata can poison model behavior.
The minimum manifest should include:

- tool name, version, server URI or local runner id;
- input schema digest and output schema digest;
- description digest and annotation digest;
- declared side effects and reversibility;
- required scopes, audience/resource, and network access;
- sandbox requirement and sandbox identity binding;
- sensitivity classes for input and output;
- allowed source zones and sink zones;
- owner/issuer key id and expiry.

Runtime calls must fail closed or enter quarantine when the live tool manifest
drifts from the trusted digest.

### Layer 3: Runtime Attestation

Runtime attestations bind a specific action to specific context. They should be
small enough to attach to MCP metadata and strong enough to export later. The
canonical statement should include:

- profile id, statement type, and schema version;
- actor, issuer, key id, tenant/scope when supplied;
- transport, protocol, tool, server, audience, and resource;
- source zone, sink zone, phase, and sandbox identity;
- action digest, payload digest, context digest, and manifest digest;
- policy verdict, matched rules, scanner stages, and quarantine state;
- confirmation token digest when human approval is required;
- nonce, issued-at, expiry, and replay scope;
- previous audit checkpoint or trace correlation reference.

The verifier must reject expired attestations, reused nonces in replay-protected
scopes, digest mismatches, missing manifest bindings, incompatible profile
versions, and unsigned statements when a trust bundle requires signatures.

### Layer 4: Boundary Policy Kernel

The policy kernel should make deterministic decisions before optional adaptive
analysis. Required inputs:

- actor trust level and supplied host principal;
- tool capability and side-effect class;
- source zone, sink zone, and payload sensitivity;
- reversibility, risk, and confirmation requirement;
- bundle trust level and revocation state;
- scanner hits and output quarantine state;
- repo path or project-local policy context when available.

Required verdicts:

- `:allow` for permitted calls;
- `:block` for prohibited calls;
- `:confirm` for calls requiring exact action approval;
- `:redact` for payload transformation;
- `:quarantine` for untrusted bundles, drifted manifests, or suspicious outputs.

### Layer 5: Evidence And Audit Export

SigilGuard already has a tamper-evident audit foundation. The profile should
standardize what evidence means:

- each decision event is digest-first and payload-minimizing;
- each event can be represented as OTel attributes and CloudEvents data;
- checkpoints can be signed;
- batch exports can include Merkle roots and inclusion proofs;
- external anchoring/WORM storage is optional and host-owned;
- SCITT-style transparency receipts can be supported later without requiring a
  networked transparency service in the core library.

## Why This Can Become A De Facto Profile

The proposed profile has a realistic standards path because it does not compete
with the large protocols. It fills a narrow missing layer:

| Existing standard | What it gives | What SigilGuard adds |
|-------------------|---------------|----------------------|
| MCP | Tool transport and authorization shape | Local trust, manifest drift checks, action attestations, output quarantine |
| A2A | Agent-to-agent interoperability | Optional attestation/evidence layer across opaque agents |
| ACP | Editor-agent integration | Policy and evidence around tool execution and file changes |
| OAuth/RFC 9728/RFC 8707 | Audience and resource binding | Offline equivalent for stdio/local tools and signed bundle context |
| TUF | Secure metadata distribution patterns | Embedded trust-bundle verification for agent tools |
| in-toto/DSSE/SLSA | Typed signed provenance | Runtime action/result attestations |
| SCITT/Sigstore | Transparency and portable verification material | Optional audit export and anchoring path |
| OTel/CloudEvents | Portable telemetry/event formats | Security-specific decision attributes and digest-first evidence |
| W3C DID/VC | Optional verifiable identity claims | Registry-optional actor and issuer references |

This is the right scope for an Elixir library: opinionated enough to be useful,
small enough to verify, and standards-aligned enough that other runtimes could
copy the same profile without adopting SigilGuard internals.

## V3 Migration Position

V3 migration means giving current users a clear upgrade path, not preserving the
old upstream architecture in runtime code.

| Surface | Forward rule |
|---------|--------------|
| Project name | Keep `SigilGuard`; `sigil` remains a project idiom. |
| `_sigil` metadata | Replace with `_agent_trust` in v3. |
| `_sigil_confirmation` | Replace with `_agent_confirmation` in v3. |
| Envelope fixtures | Move to historical migration fixtures, not v3 proof. |
| `SigilGuard.Registry` | Remove from v3 public API and docs. |
| Remote bundle fetch | Host-owned transport outside core. |
| New architecture | Use trust bundle, capability manifest, attestation, policy, quarantine, and evidence vocabulary. |

## Design Decisions

### Adopted

- SigilGuard defines its own embedded Agent Trust Profile.
- The profile is local-first and registry-free by default.
- Tool manifests are supply-chain inputs and must be hash-bound or signed.
- Runtime decisions are typed attestations over canonical digests.
- Scanning becomes one stage in a staged boundary pipeline.
- Confirmation tokens bind to exact action digests and context.
- Output quarantine is a first-class verdict.
- Audit exports become digest-first evidence with optional anchoring.
- Legacy SIGIL material is limited to migration docs and historical fixtures.

### Rejected

- A public hosted registry as the default trust path.
- An internal HTTP registry as the core abstraction.
- A model-provider-specific security layer.
- A scanner-only security model.
- Unsigned live tool metadata as trusted context.
- Compatibility wording that lets old protocol vocabulary drive runtime design.

### Deferred

All items originally deferred by this note are now resolved by follow-up
research notes:

- External profile encoding: resolved by
  [R.02](R.02-attestation-envelope-and-canonical-encoding.md) — DSSE envelope
  over JCS-canonical in-toto-style Statement payloads.
- DID/VC support: resolved by
  [R.05](R.05-actor-identity-delegation-and-a2a.md) — claim references only,
  SPIFFE-shaped identifiers recommended, optional `did:key` acceptance.
- SCITT transparency receipts: resolved by
  [R.04](R.04-audit-proofs-witnessing-and-privacy.md) — optional post-GA
  adapter, never core.
- Adaptive anomaly detection: resolved by
  [R.07](R.07-runtime-dependencies-and-interoperability.md) — behaviour
  in core with a deterministic nil-path; reference implementation in an
  optional post-GA package.

## Impact On SigilGuard

- Modules affected: `SigilGuard.Registry`, `SigilGuard.Registry.Bundle`,
  `SigilGuard.Registry.Cache`, `SigilGuard.Patterns`, `SigilGuard.Envelope`,
  `SigilGuard.MCP.Gateway`, `SigilGuard.Runtime.Gate`,
  `SigilGuard.Confirmation`, `SigilGuard.Audit.*`, `SigilGuard.RepoPolicy`,
  future `SigilGuard.TrustProfile`, future `SigilGuard.TrustBundle`, and future
  `SigilGuard.Attestation`.
- Specs to create/update: `SP.01`, `SP.02`, `SP.03`, `SP.04`, `SP.05`, the new
  `SP.13` (agent-to-agent trust statements), `SP.14` (ecosystem integrations
  and adoption), and `SP.15` (benchmark methodology), plus downstream contract
  specs where existing modules already implement part of the profile.
- Migration needed: yes, with a v2-to-v3 guide and changelog section.
- Breaking changes: yes. V3 should remove registry/protocol surfaces from the
  public runtime API.

## Implementation Implications

### SP.01: Agent Trust Profile

`SP.01` should define the profile id, statement types, required digests,
canonical encoding rules, v3 breaking boundary, replay semantics, and
validation errors.

### SP.02: Embedded Trust Bundles

`SP.02` should treat bundles as local signed metadata, not registry rows.
Required controls: root keys, delegated issuers, sequence numbers, expiry,
revocation, rollback floor, threshold-ready signatures, quarantine, and
network-free verification.

### SP.03: MCP Attestation Gateway

`SP.03` should bind MCP request and result verification to actor, server URI,
tool, manifest digest, scopes, resource/audience, source/sink zone, transport,
nonce, and policy verdict. HTTP MCP should align with OAuth resource indicators;
stdio/local MCP should use bundle-provided resource context. Wrong audience,
token passthrough, manifest drift, schema drift, and unsandboxed privileged tools
are explicit deny cases.

### SP.04: Boundary Scanner And Policy Kernel

`SP.04` should model the scanner as a staged pipeline:

1. manifest and bundle validation;
2. static metadata poisoning checks;
3. input sensitivity scanning;
4. policy decision;
5. confirmation gate;
6. result scanning;
7. output quarantine or release;
8. audit evidence emission.

### SP.05: Audit And Release Provenance

`SP.05` should align audit events with OTel and CloudEvents, extend checkpoint
exports with signed roots, preserve privacy by default, and leave external/WORM
anchoring as host-owned adapters.

## Validation Strategy

| Test family | Required evidence |
|-------------|-------------------|
| Canonical vectors | Stable bytes for bundle, manifest, attestation, confirmation token, and audit event statements. |
| Tamper tests | Digest, key id, issuer, manifest, policy, and payload drift are rejected. |
| Replay tests | Nonce reuse and expired attestations fail in replay-protected scopes. |
| Rollback tests | Older bundle sequence numbers fail unless explicitly allowed for recovery. |
| Quarantine tests | Invalid bundles, drifted manifests, suspicious outputs, and unsigned/untrusted material quarantine cleanly. |
| MCP tests | HTTP and stdio contexts bind actor, resource, scopes, server, tool, and transport. |
| Scanner tests | Pipeline stages preserve source/sink labels and cannot release quarantined output accidentally. |
| Audit tests | Event digests, signed checkpoints, Merkle roots, and export verification are deterministic. |
| Migration tests | Old `_sigil`, confirmation, envelope, and registry-named API examples map to documented v3 replacements. |
| Negative network tests | Default operation performs no public registry or discovery calls. |
| Coverage and gates | Maintain >= 95% line coverage and clean project quality gates. |

## Research-Derived Design Rules

- **Never trust tool metadata because it arrived through MCP.** Treat metadata as
  signed supply-chain material.
- **Never sign untyped maps.** Sign profile-scoped statements with canonical
  bytes and explicit payload types.
- **Never make remote discovery the default trust boundary.** The default
  verifier is local and embedded.
- **Never release untrusted tool output directly into model context.** Route it
  through result scanning, source/sink policy, and quarantine decisions.
- **Never let approval tokens authorize fuzzy intent.** Bind confirmation tokens
  to exact action, payload, context, actor, tool, and expiry digests.
- **Never emit raw secrets into audit evidence by default.** Emit digests,
  classifications, decision metadata, and redacted excerpts only when configured.
- **Never make ML required for correctness.** Optional adaptive detection can
  improve signal, but deterministic policy remains authoritative.
- **Never make old SIGIL vocabulary the center of new APIs.** Keep it in
  migration docs or historical fixtures only.

## Open Questions (All Resolved)

All questions this note originally left open are now closed:

- External bytes encoding: closed by
  [R.02](R.02-attestation-envelope-and-canonical-encoding.md) — JCS-canonical
  Statement payloads inside DSSE envelopes; no separate internal encoder for
  external bytes.
- Attestation envelope: closed by
  [R.02](R.02-attestation-envelope-and-canonical-encoding.md) — DSSE is the
  public envelope in v3 from the start.
- Bundle credential claims: closed by
  [R.05](R.05-actor-identity-delegation-and-a2a.md) and
  [R.03](R.03-trust-bundle-role-model.md) — v1 bundles carry issuer/key
  references; VC-style credentials remain optional opaque references.
- Compatibility namespace: closed by
  [R.07](R.07-runtime-dependencies-and-interoperability.md) — no
  `SigilGuard.Compatibility` namespace; `MIGRATING-1.0.md` and the changelog
  carry the migration.
- Adaptive scanning: closed by
  [R.07](R.07-runtime-dependencies-and-interoperability.md) — behaviour
  in core with a deterministic nil-path; the reference detector ships as an
  optional post-GA package.

## Recommendation

**Decision:** adopted.

SigilGuard should implement the SigilGuard Agent Trust Profile as the primary
future architecture. The profile should be embedded, local-first,
transport-agnostic, signed, canonical, deterministic by default, and
evidence-oriented. It should compose with current agent protocols rather than
compete with them. Historical SIGIL material should remain only in migration
docs and historical fixtures.

## Sources

- [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [Hex package: sigil_guard](https://hex.pm/packages/sigil_guard)
- [A2A Protocol](https://github.com/a2aproject/A2A)
- [Agent Client Protocol](https://agentclientprotocol.com/get-started/introduction)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
- [OWASP MCP Tool Poisoning](https://owasp.org/www-community/attacks/MCP_Tool_Poisoning)
- [CSA Agentic MCP Security Best Practices](https://labs.cloudsecurityalliance.org/agentic/agentic-mcp-security-best-practices-v1/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [Agentic AI Risk-Management Standards Profile](https://cltc.berkeley.edu/publication/agentic-ai-risk-profile/)
- [RFC 9728 - OAuth 2.0 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [RFC 8707 - Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/info/rfc8707)
- [RFC 9421 - HTTP Message Signatures](https://datatracker.ietf.org/doc/rfc9421/)
- [RFC 8785 - JSON Canonicalization Scheme](https://www.rfc-editor.org/info/rfc8785)
- [CloudEvents](https://cloudevents.io/)
- [OpenTelemetry AI Agent Observability](https://opentelemetry.io/blog/2025/ai-agent-observability/)
- [RFC 9162 - Certificate Transparency Version 2.0](https://datatracker.ietf.org/doc/html/rfc9162)
- [W3C DID Core](https://www.w3.org/TR/did-core/)
- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [The Update Framework Specification](https://theupdateframework.github.io/specification/latest/)
- [RFC 9943 - SCITT Architecture](https://datatracker.ietf.org/doc/rfc9943/)
- [SLSA Build Provenance](https://slsa.dev/spec/v1.2/build-provenance)
- [Sigstore Bundle Format](https://docs.sigstore.dev/about/bundle/)
- [in-toto Attestation Framework](https://github.com/in-toto/attestation)
- [Prompt Injection Attacks on Agentic Coding Assistants](https://arxiv.org/abs/2601.17548)
- [Model Context Protocol Threat Modeling and Analysis of Tool Poisoning](https://arxiv.org/html/2603.22489v1)
- [AgentDyn: Dynamic Prompt Injection Benchmarking](https://arxiv.org/html/2602.03117v1)
- [MCPTox: Tool Misuse and Toxicity in MCP Agents](https://arxiv.org/html/2508.14925v1)
- [Original SIGIL repository](https://github.com/sigil-eu/sigil)
- [sigil-protocol crate documentation](https://docs.rs/sigil-protocol)
