---
sigil_guard:
  id: "R.07"
  topic: "Ecosystem Positioning, Dependencies, And Adoption"
  category: research
  status: complete
  created: "2026-07-02"
  updated: "2026-07-02"
  decision: adopted
  tags:
    [
      "ecosystem",
      "dependencies",
      "adoption",
      "integrations",
      "adaptive-detection",
      "release-engineering",
      "positioning"
    ]
---

# R.07 - Ecosystem Positioning, Dependencies, And Adoption

## Executive Summary

The mid-2026 Elixir ecosystem has exactly one other MCP/LLM security package,
and it does not compete on architecture. SigilGuard v3 can therefore claim and
defend a real niche: the only production-grade embedded Elixir security
runtime for MCP and agent-tool boundaries. This note records four adopted
decisions that make the claim credible: core runtime dependencies are kept
minimal and individually justified rather than driven to zero - `:telemetry`,
`:nimble_options`, and a JSON library (Jason) - on an Elixir `~> 1.18` floor
justified by OTP 27 crypto and set-theoretic types (D9); adaptive/ML detection
is a core behaviour with a deterministic nil-path while the model-backed
reference implementation is deferred to an optional post-GA package (D5); v3
ships no compatibility namespace and migrates users through `MIGRATING-1.0.md`
and the changelog only (D6); and the release sequence is a direct manual
alignment to `1.0.0`, followed by git_ops, package, and reference-consumer
validation (D11). It also
fixes Tier 1 integration targets (hermes_mcp, Jido, LangChain/ReqLLM,
Tidewave) and the adoption playbook that SP.14 and SP.15 turn into tasks.

## Research Question

What ecosystem position, dependency posture, adaptive-detection stance,
compatibility stance, and release/adoption sequence should SigilGuard v3
adopt?

Five sub-questions:

1. Does the claimed niche exist, or does an incumbent already occupy it in
   Elixir or nearby ecosystems?
2. Which runtime dependencies does the v3 core keep, on what individual
   merits, and what replaces the ones it drops?
3. Where does ML-backed detection live relative to the deterministic core?
4. Does v3 carry a compatibility namespace for 0.2.x users, or documentation
   only?
5. How do 0.2.x and 1.0.0 coexist on Hex, and which artifacts and channels
   make the library visible to its audience?

## Methodology

- Hex.pm package pages were used for download counts, versions, and reverse
  dependencies, accessed 2026-07-02. These figures are post-knowledge-cutoff
  observations and are recorded as accessed values, not durable facts.
- MCP specification-repository material was used for the interceptor
  extension model (SEP-1763 issue, the experimental reference implementation
  repository, and the Interceptors Working Group charter).
- Primary vendor and release material: elixir-lang.org release and
  certification announcements, Dashbit/Tidewave documentation, Hugging Face
  model cards, OpenSSF Best Practices, and OpenTelemetry GenAI semantic
  conventions.
- Internal evidence: `mix.exs` on the `native` branch (finch `~> 0.19`,
  jason `~> 1.4`, telemetry `~> 1.0`, floor `~> 1.17`), module-level usage
  (Jason referenced in 13 files; finch consumed by the legacy remote bundle
  path, application wiring, and the audit HTTP anchor store), and the
  reference-consumer inventory (44 call sites behind five wrapper seams).
- Conflict handling: vendor-published statements are preferred over press
  coverage; press-reported figures such as acquisition prices are marked as
  reported; latency and size figures without vendor benchmarks are marked as
  working estimates.

## Context

V3 repositions SigilGuard from a protocol port to a standalone embedded
security runtime. Positioning, dependency posture, and release mechanics are
not marketing afterthoughts here: for a security library, every dependency is
an auditable claim that must justify itself on merit, the migration story is a
trust signal, and the integration surface decides whether anyone deploys it. A
dependency count is not a marketing metric; the right posture is minimal and
well-justified, not zero. CLAUDE.md rule 8
forbids remote network calls in core decision paths without an explicit
trust, timeout, retry, and failure model, which directly constrains how the
one legitimate HTTP feature (audit anchoring) survives dependency removal.
The reference consumer (a production agent runtime that embeds SigilGuard)
runs Elixir 1.19 and isolates the library behind wrapper modules, which
bounds the real-world migration cost of every decision below. These
decisions gate the mix.exs work in milestones M1 and M6, the
`SigilGuard.HTTPClient` behaviour in SP.05, the dependency-removal section
in SP.12, and the two new specs SP.14 (integrations and adoption) and SP.15
(benchmarks).

## Findings

### The Elixir Competitive Field Is Effectively Empty

The only other Elixir package in this space is `llm_guard` 0.3.1: roughly
749 all-time downloads and about 316 in the last month, a single maintainer,
and a scanner-shaped API (prompt-injection and content checks). It has no
runtime gate, no signed trust bundles, no capability manifests, and no
tamper-evident audit chain (accessed 2026-07-02). It is a useful scanner,
not an embedded trust runtime.

Cross-language competitors cluster into three non-embedded shapes:

- Gateway proxies that sit in front of MCP servers and route traffic through
  a separate process or container.
- Guardrail model stacks (LlamaFirewall with Prompt Guard 2, NeMo
  Guardrails) that are Python-native and model-dependent.
- Scanners and hosted APIs. The strongest commercial signal is Lakera, whose
  guardrail platform was acquired by Check Point in a deal announced in
  September 2025 and reported by the press at about USD 300M (the vendor
  release does not state a price; accessed 2026-07-02). The category is
  valuable and consolidating toward proxies and SaaS, not embedded
  libraries.

None of these run in-process on the BEAM, and none combine signed trust
material, deterministic policy, and tamper-evident evidence in one embedded
package. The positioning claim "the only production-grade embedded Elixir
security runtime for MCP and agent-tool boundaries" is supported by the
accessed evidence and is falsifiable by a Hex search, which is exactly what a
positioning claim should be.

| Property | Embedded SigilGuard | Gateway proxy | Hosted guardrail API |
|----------|---------------------|---------------|----------------------|
| Call-path cost | In-process function call; no sidecar hop | Extra network hop per tool call | Remote round trip per check |
| Failure model | OTP supervision inside the host app | Separate process/container to deploy and monitor | Vendor availability plus egress path |
| Determinism | Deterministic verdicts with golden vectors | Varies by product | Model-based, non-deterministic |
| Evidence | Signed local audit chain, exports, anchors | Proxy logs | Vendor-held logs |
| Adoption cost | MIT Hex dependency; no infrastructure | New infrastructure and traffic routing | Contract, keys, and data egress |

### Current Dependencies And The Elixir 1.18 Floor

`mix.exs` today declares three runtime dependencies: `finch ~> 0.19`,
`jason ~> 1.4`, and `telemetry ~> 1.0`, with an Elixir floor of `~> 1.17`.

Jason is referenced in 13 files and stays. It is ubiquitous, battle-tested,
and already transitively present in effectively every consumer (Phoenix,
Ecto, and most HTTP clients pull it in), so it adds no practical
supply-chain surface a host does not already carry, and it is the reference
JSON library the wider ecosystem is written against. Elixir v1.18 (released
2024-12-19) did ship a standard-library `JSON` module whose basic API
deliberately reflects Jason's and whose encoder and decoder conform to
RFC 8259 and ECMA 404, and it is an acceptable drop-in alternative on OTP 27;
but it is not required, and swapping a working, universally present
dependency for stdlib parity buys nothing on merit. The Elixir floor still
rises from `~> 1.17` to `~> 1.18`, now justified by OTP 27 crypto primitives
and set-theoretic types rather than by JSON, and the reference consumer
already runs 1.19, so the bump is safe for the known install base.

Finch has four consumers in the tree: the legacy remote bundle path
(`SigilGuard.Registry`), the application/facade wiring that exists to serve
that path, and the audit HTTP anchor store. The legacy remote bundle path is
deleted in v3 per SP.12, which removes finch's only consumer of substance;
finch therefore leaves the core because its consumer is gone, not on any
dependency-purity ground. The anchor store is the one legitimate remaining
HTTP need, and it is optional, host-triggered, and outside the core decision
path. Converting it to a host-provided `SigilGuard.HTTPClient` behaviour is a
security and ownership decision, not a way to shed a dependency: CLAUDE.md
rule 8 forbids network in core decision paths, and the project charter puts
transport ownership with the host. The behaviour makes the timeout, retry,
and failure model an explicit documented contract in SP.05. An optional
`req`-based default anchor client MAY ship as an optional dependency for
hosts that want a batteries-included store; it is an option a host can pull
in, never a core requirement. Evidence classification per the research
discipline: the anchor-store conversion is optional internal HTTP
compatibility; the removed remote bundle fetch was already a rejected public
discovery model.

Telemetry stays. It is the BEAM-wide observability standard, is itself a
tiny dependency-free Erlang library, and is already pulled in by effectively
every production Phoenix/Ecto/Oban application, so it adds no practical
supply-chain surface while enabling the evidence-oriented instrumentation
the profile requires.

### NimbleOptions Is Adopted For Validated Config Schemas

NimbleOptions is the conventional choice for options validation in modern
Elixir libraries, and v3 adopts it. An earlier draft rejected it "for the
zero-dep core"; that stance is reversed. It is Dashbit-maintained, carries no
transitive dependencies, and provides compile-time-validated option schemas
with generated documentation. For a security library, a declarative,
well-exercised schema validator is strictly safer than hand-rolled checks:
the fail-closed behaviour (unknown keys, wrong types, and removed keys
produce typed errors) becomes data the library declares once rather than
imperative code it must get right by hand at every call site, and the
generated docs keep the configuration contract and its documentation in
sync. SigilGuard's config surface is small and security-sensitive, which is
exactly the surface where a validated schema earns its place. NimbleOptions
is judged on that merit, not on whether it raises a dependency count.

### Adaptive Detection: Mature Substrate, Wrong Weight For Core

The ML substrate in Elixir is real: Nx (about 1.4M all-time downloads) and
Bumblebee (about 422k) are established, and Ortex provides ONNX Runtime
bindings suitable for classifier inference (figures accessed 2026-07-02).

Candidate models for prompt-injection classification are also concrete:

- `protectai/deberta-v3-base-injection-onnx`, the ONNX conversion maintained
  for the Python llm-guard scanner's CPU inference path. On-disk weights are
  in the 200-400 MB range and single-input CPU inference lands in the
  100-500 ms range; both are working estimates for capacity planning, not
  vendor-published benchmarks.
- Llama Prompt Guard 2 (22M and 86M variants): much smaller classifiers for
  injection and jailbreak detection with a 512-token window; the 86M variant
  is multilingual.

Three properties disqualify any of these from the v3 core: weight (hundreds
of megabytes against a library that installs in seconds), latency (hundreds
of milliseconds against a sub-millisecond deterministic pipeline), and
non-determinism (model verdicts cannot be golden-vector tested and must
never be authoritative). None of them argue against a behaviour seam, which
costs nothing at runtime when unconfigured. The established optional-
dependency pattern (a `Code.ensure_loaded?/1` guard plus an explicit config
feature flag, as used by Oban, Ecto, and Phoenix for `opentelemetry_api`)
lets a separate package supply the model-backed detector after GA without
the core ever taking Nx, Ortex, or Bumblebee as dependencies.

### Hex Evidence Against A Compatibility Namespace

The `sigil_guard` package shows about 180 all-time downloads and no visible
reverse dependencies (first recorded 2026-07-01 in R.01, re-checked
2026-07-02). The measurable migration population is therefore the reference
consumer plus unknown direct-Git users. That consumer concentrates its 44
call sites behind five wrapper seams; its envelope/`_sigil` usage is exactly
2 call sites, and its SigilGuard config change is the deletion of registry
and backend keys. The expected migration diff for the only known production
consumer is roughly two call-site edits plus config removal.

A `SigilGuard.Compatibility` namespace would preserve deleted architecture
(legacy remote bundle modules, the old envelope) for an audience the data
says does not exist, double the security-test surface for those modules, and
contradict the v3 positioning. Documentation-only migration is the
proportionate answer, with historical golden vectors retained under
`test/fixtures/historical/` as migration evidence rather than runtime
behavior.

### Release Mechanics: What git_ops And Hex Actually Allow

Three mechanical facts shape D11:

- git_ops derives the next version from conventional-commit history and the
  current mix.exs version. It cannot infer the intended 0.2.x-to-1.0.0 jump
  from history, so the 1.0.0 version must be set manually and git_ops must be
  re-verified afterwards with a dry run.
- `~> 0.2` remains pinned to the legacy line and does not auto-upgrade to
  1.0.0, so consumers opt into the breaking release by changing their
  dependency requirement to `~> 1.0`.
- The reference consumer should move to `~> 1.0` only after the published
  package validates, keeping local path validation separate from production
  dependency updates.

### Tier 1 Integration Targets

Reach figures accessed 2026-07-02.

| Target | Reach | Extension point | SigilGuard insertion |
|--------|-------|-----------------|----------------------|
| hermes_mcp | ~171k all-time | Interceptors (SEP-1763 model), middleware, plugs | Pre/post tool-call gate |
| jido | ~84k all-time, ~56k/month, v2.3.x | Tool wrappers and pre-execution hooks | Action gating before execution |
| langchain | ~747k all-time, ~179k/month | Composable chain steps | Gating step around tool calls and responses |
| req_llm | ~246k all-time, ~173k/month | Req-style pipeline steps | Request/response gating step |
| tidewave (Dashbit) | Phoenix/Rails runtime MCP tools | MCP tools into the live runtime | Gating showcase for high-risk tools |

Notes per target:

- **hermes_mcp** is the dominant Elixir MCP SDK. The MCP ecosystem is
  standardizing interceptors via SEP-1763 (validator and mutator hooks
  around tool discovery, tool invocation, and other lifecycle points, with a
  multi-language reference implementation and a chartered working group);
  hermes_mcp exposes interceptor, middleware, and plug seams that give
  SigilGuard exactly the pre/post tool-call insertion the gate needs.
  `anubis_mcp` is a community fork with the same extension model, so one
  guide covers both.
- **Jido** is the leading Elixir agent framework; its tool-wrapper and
  pre-execution hook points map directly onto `guard`/`policy_verdict`
  placement around actions.
- **LangChain Elixir and ReqLLM** have the largest reach; a composable
  gating step covers tool execution and prompt/response scanning in both
  without SigilGuard taking either as a dependency.
- **Tidewave** is the highest-leverage showcase: its runtime-introspection
  MCP tools (code evaluation, SQL, logs against a live app) are precisely
  the tool class that most needs gating, and Phoenix 1.8 generating
  AGENTS.md by default marks the era in which Phoenix apps are
  agent-navigable out of the box.

### Tier 2 Targets

`ex_mcp` (about 3.8k all-time, release-candidate status), Vancouver
(pre-0.1), and `mcp_sse` are tracked but get no guides until their APIs
stabilize or adoption justifies the maintenance (figures accessed
2026-07-02).

### Delivery Model For Integrations

Integrations ship as ExDoc guides plus an `examples/` directory with pinned
target versions and a documented manual compile-validation procedure.
SigilGuard takes zero hard dependencies on any integration target.
CI-maintained example applications are deferred post-GA; pinned examples
keep the maintenance cost proportional to Tier 1's release cadence.

### Adoption Signals That Move Elixir Libraries

The libraries that trend in this ecosystem share a reproducible artifact
set: ExDoc cheatsheets, livebooks with Run in Livebook badges, 100% doc
coverage, clean dialyzer, disciplined changelogs, published benchmarks, a
SECURITY.md, and visible supply-chain hygiene. The channels are equally
consistent: ElixirForum announcements, Elixir Radar, the Thinking Elixir
podcast, ElixirConf talks, and awesome-elixir listing.

Two alignment facts strengthen the supply-chain story specifically for
SigilGuard: Elixir itself has been OpenChain ISO/IEC 5230 certified since
2025-02-26 and ships attested source SBOMs (CycloneDX 1.6+/SPDX 2.3+) with
its releases, so a security library that publishes SLSA provenance and SBOMs
matches the language's own posture rather than inventing one. And on
observability, the OpenTelemetry GenAI semantic conventions (`gen_ai.*`)
remain experimental, so the stable pattern used by Oban, Ecto, and Phoenix
applies: keep library-owned telemetry events as the contract and offer
`opentelemetry_api` attribute mapping as an optional dependency.

## Comparative Analysis

The dependency posture is a three-way choice, evaluated for a security
library: zero-dep purism, a kitchen-sink baseline, and minimal-and-justified.

| Criterion | Zero-dep purism (telemetry only) | Kitchen sink (finch + transitive tree in core) | Minimal and justified (telemetry + nimble_options + jason) |
|-----------|----------------------------------|------------------------------------------------|------------------------------------------------------------|
| Supply-chain surface | Smallest possible, but pays for it in hand-rolled code the library must audit itself | finch's transitive tree (mint, nimble_pool, castore, hpax) lives in core as audit surface with no core consumer | telemetry (dependency-free), nimble_options (Dashbit, no transitive deps), jason (already present in every consumer); each entry answers for itself |
| Validation safety | Hand-rolled fail-closed checks: bounded but imperative code to get right at every call site | Same hand-rolled burden, plus more surface | Declarative NimbleOptions schemas with compile-time validation and generated docs; strictly safer for security config |
| Positioning claim | "Zero deps": a count, not a merit; brittle and self-defeating when it forces worse code | "Few deps": unremarkable and unverifiable | "Every dependency is justified on merit": an auditable, defensible claim |
| Maintenance | Maintain the hand-rolled validators forever | Track finch releases, advisories, and floor interactions for a feature core does not use | Track three well-maintained deps; HTTP maintained by the host behind a behaviour |
| Host friction | None from deps, but consumers re-derive JSON they already have | Possible finch version conflicts with hosts that pin their own | jason is already in the tree; hosts bring their own HTTP client behind the behaviour |

Minimal-and-justified wins: it beats zero-dep purism by refusing to trade a
validated schema library for hand-rolled code purely to lower a count, and it
beats the kitchen sink by keeping finch (and its transitive tree) out of core
once its only consumer is deleted. Its total cost is the `~> 1.18` floor
(safe: 1.18 released 2024-12, 1.19 stable since 2025-10, the known production
consumer already on 1.19, and the floor is justified by OTP 27 crypto and
set-theoretic types), one HTTPClient behaviour module, and the small, bounded
NimbleOptions schemas for the config surface.

## Decision Records

### D9: Core Runtime Dependencies (Adopted, Revised)

Posture: dependencies are minimal and well-justified, not zero. Each is
judged individually on merit; a dependency count is never a marketing metric.
This reverses the earlier "zero-dep core" rule and its Jason-drop and
NimbleOptions-rejection mandates.

- V3 core runtime dependencies MUST be `:telemetry`, `:nimble_options`, and a
  JSON library (`jason`). Adding any further runtime dependency MUST be
  justified on its own merit in a spec or research note.
- The Elixir floor MUST rise from `~> 1.17` to `~> 1.18`, justified by OTP 27
  crypto primitives and set-theoretic types, NOT by JSON.
- `jason` MUST stay. It is ubiquitous, battle-tested, and already
  transitively present in consumers. The stdlib `JSON` module (OTP 27) is an
  acceptable alternative but is NOT required; the earlier mandate to drop
  Jason for built-in JSON is reversed.
- `:nimble_options` MUST be adopted for configuration and option validation:
  compile-time-validated schemas with generated docs, Dashbit-maintained,
  with no transitive dependencies. It is strictly safer than hand-rolled
  validation for a security library. Its unknown-key, wrong-type, and
  removed-legacy-key handling MUST fail closed with typed errors. The earlier
  rejection of NimbleOptions "for the zero-dep core" is reversed.
- `finch` MUST leave the core, because the legacy remote bundle path that was
  its only real consumer is removed in v3 per SP.12 - not on dependency-purity
  grounds. The audit HTTP anchor store MUST consume a host-provided
  `SigilGuard.HTTPClient` behaviour whose timeout, retry, and failure model
  SP.05 documents. That behaviour exists for security (no network in core
  decision paths, CLAUDE.md rule 8) and host-owns-transport, NOT to avoid a
  dependency. Configuring the HTTP anchor store without a client
  implementation MUST be a typed startup error, never a silent no-op. An
  optional `req`-based default anchor client MAY ship as an optional
  dependency; it is an option, not a requirement.
- Scope: this rule governs runtime dependencies only. Dev and test
  dependencies (credo, dialyxir, sobelow, mix_audit, ex_check, ex_doc,
  doctor, excoveralls, mox, benchee, stream_data, git_ops, and similar)
  remain exempt.
- M6 MUST land an assertion test that fails whenever the runtime dependency
  set differs from the intended set (`:telemetry`, `:nimble_options`,
  `jason`) plus OTP/stdlib applications, so unaudited dependency creep is
  caught in CI.

### D5: Adaptive Detection (Adopted)

- The v3 core MUST define an adaptive-detector behaviour with a
  deterministic nil-path default: with no detector configured, pipeline
  behavior is identical to a build without the seam, and every verdict
  remains deterministic and golden-vector testable.
- Detector output MUST be advisory input to the deterministic policy kernel.
  It MUST NOT override or bypass deterministic verdicts.
- The model-backed reference implementation (Ortex/ONNX running
  `protectai/deberta-v3-base-injection-onnx`, or Llama Prompt Guard 2
  22M/86M) is deferred to an optional post-GA package. The core stays
  zero-ML: no model weights and no Nx, Ortex, or Bumblebee dependencies.
- Optional integration MUST use the optional-dependency pattern: a
  `Code.ensure_loaded?/1` guard plus an explicit config feature flag. An
  enabled flag without the package present MUST be a typed startup error,
  not silent degradation.
- SP.04 owns the behaviour contract, callbacks, and error atoms.

### D6: No Compatibility Namespace (Adopted)

- V3 MUST NOT ship a `SigilGuard.Compatibility` namespace or any equivalent
  runtime shim layer.
- Legacy modules (the legacy remote bundle namespace, `SigilGuard.Envelope`,
  and `SigilGuard.Profile`) are deleted in M6, not hidden, wrapped, or
  deprecated in place.
- The migration surface is `MIGRATING-1.0.md` plus the CHANGELOG, with a 1:1
  old-to-new mapping for every removed public API.
- Historical golden vectors MUST move to `test/fixtures/historical/` and
  remain in the test tree as migration evidence only.
- Basis: about 180 all-time downloads with no visible reverse dependencies,
  and a known-consumer migration diff of roughly 2 call sites plus config
  removal behind five wrapper seams.

### D11: Release Sequence (Adopted)

1. **Manual 1.0.0 alignment.** Perform a manual version jump on `main`:
   git_ops cannot infer the intended 0.2.x-to-1.0.0 jump from commit history.
   Set the mix.exs version, migration guide, changelog, generated fixtures,
   package metadata, and release docs together.
2. **git_ops resume check.** Verify git_ops resumes correctly with a dry run
   from the new version line after the manual alignment.
3. **Package and reference-consumer gate.** Build the package, verify the
   migration guide and docs point at `MIGRATING-1.0.md`, and validate the
   reference consumer against the package before changing production
   dependency requirements.
4. **1.0.0.** Publish GA, confirm git_ops operates normally from the new
   version line, and move
   the reference consumer to `~> 1.0`.

## Recommendation

**Decision:** adopted.

All four decision areas above are adopted, together with the Tier 1/Tier 2
integration tiering, the delivery model, and the adoption playbook below.
This closes R.01's fourth Deferred item (whether adaptive anomaly detection
belongs in the main package or an optional provider behaviour) and R.01 Open
Questions 4 (compatibility namespace versus `MIGRATING-1.0.md`) and 5
(adaptive scanning as a core behaviour versus a separate package), and it
closes the task-list open decisions on adaptive detectors, the compatibility
namespace, and the release sequence.

**Rationale:** The niche is real and empty; the only Elixir neighbor is a
single-maintainer scanner without gate, bundle, or audit architecture, and
the cross-language competition is structurally non-embedded. For a security
library, every dependency is a claim that must survive an audit, and the
defensible posture is minimal and well-justified rather than zero: keep
`telemetry`, adopt `nimble_options` for validated config schemas, keep
`jason`, and drop finch by deleting its only consumer. That is stronger than
a bare dependency count, which forces worse hand-rolled code the moment it is
treated as a goal. Determinism is the product's differentiator, so ML stays
optional and advisory forever. The download data makes compatibility
machinery pure cost with no beneficiary. And the release sequence is honest
to an install base of roughly 180 downloads while protecting rc consumers
from the prerelease-resolution trap.

### Adopted Adoption Playbook

Positioning statement: SigilGuard is the only production-grade embedded
Elixir security runtime for MCP and agent-tool boundaries.

Tagline for README, Hex, and talks: "In-process. OTP-supervised.
Deterministic. No sidecar. Signed evidence."

Artifacts (SP.14 owns acceptance criteria; SP.15 owns benchmark rules):

- ExDoc cheatsheets (`.cheatmd`) covering the gate, policy, and audit APIs.
- Five livebooks with Run in Livebook badges, each executing top-to-bottom
  offline via `Mix.install` on a local path: quick-start; policy and the
  lethal trifecta; audit export and proofs; hermes_mcp integration; and
  threat scenarios.
- 100% documentation coverage enforced by `mix doctor`; dialyzer clean.
- Published benchmarks per SP.15, including an honest scanner-scope-only
  comparison against Python llm-guard: same corpus, versions disclosed, and
  no claims beyond the shared scanning scope.
- SECURITY.md with a responsible-disclosure process, and the OpenSSF Best
  Practices badge worked through bestpractices.dev.
- Signed releases, SLSA Build L3 provenance via GitHub's
  attest-build-provenance action, and SBOMs from the existing SPDX mix
  task, explicitly aligned with Elixir's own OpenChain-certified,
  SBOM-attested release posture.
- Announcement kit gated on 1.0.0 GA: ElixirForum post, Elixir Radar pitch,
  Thinking Elixir pitch, ElixirConf US CFP (date-gated), awesome-elixir PR,
  and curated Hex keywords.

Integration delivery: Tier 1 guides (hermes_mcp with the anubis_mcp note,
Jido, LangChain/ReqLLM, and the Tidewave showcase) ship as ExDoc guides plus
pinned `examples/`; Tier 2 targets are tracked without guides; CI example
apps stay deferred.

Telemetry/OTel stance: the `[:sigil_guard, ...]` telemetry events remain the
stable observability contract. An `opentelemetry_api` attribute mapping is
offered through the optional-dependency pattern. Because `gen_ai.*`
semantic conventions are still experimental, SigilGuard emits
sigilguard-owned attributes with a documented mapping guide; the final
attribute prefix decision is recorded in SP.05 (D16).

## Impact On SigilGuard

- Modules affected: `mix.exs` (floor `~> 1.18`; runtime deps set to
  `:telemetry`, `:nimble_options`, and `jason`; adopt `nimble_options` for
  config/option schemas; M6 removes finch by deleting its consumer and lands
  the dependency-set assertion test);
  `SigilGuard.Audit.Anchor.Store.HTTP` (rebuilt on the new
  `SigilGuard.HTTPClient` behaviour); the legacy remote bundle namespace,
  `SigilGuard.Envelope`, and `SigilGuard.Profile` (deleted in M6 per SP.12
  and SP.06); the scanner pipeline (adaptive-detector behaviour seam per
  SP.04); `SigilGuard.Telemetry` (optional OTel attribute mapping).
- Specs to create/update: SP.05 (`SigilGuard.HTTPClient` behaviour contract
  and OTel prefix resolution), SP.12 (dependency-removal and
  release-sequence sections), SP.04 (adaptive-detector behaviour), new
  SP.14 (ecosystem integrations and adoption), new SP.15 (benchmark
  methodology and llm-guard comparison fairness rules).
- Migration needed: yes. `MIGRATING-1.0.md` carries a 1:1 mapping for every
  removal; no runtime compatibility namespace; historical vectors move to
  `test/fixtures/historical/`.
- Breaking changes: yes. Elixir floor 1.17 to 1.18, adoption of
  `nimble_options` and removal of finch from the dependency contract (jason
  stays), deletion of legacy modules, and the major version jump sequenced
  per D11.

## Sources

Hex download figures and competitor stats are post-cutoff observations
recorded as accessed values (accessed 2026-07-02 unless noted).

- [Hex: sigil_guard](https://hex.pm/packages/sigil_guard) - ~180 all-time
  downloads, no visible reverse dependencies (first recorded 2026-07-01 in
  R.01; re-checked 2026-07-02).
- [Hex: llm_guard](https://hex.pm/packages/llm_guard) - 0.3.1, ~749
  all-time downloads, ~316/month (accessed 2026-07-02).
- [Hex: hermes_mcp](https://hex.pm/packages/hermes_mcp) - ~171k all-time
  downloads (accessed 2026-07-02).
- [Hex: anubis_mcp](https://hex.pm/packages/anubis_mcp) - community fork of
  hermes_mcp (accessed 2026-07-02).
- [Hex: jido](https://hex.pm/packages/jido) - ~84k all-time, ~56k/month,
  v2.3.x (accessed 2026-07-02).
- [Hex: langchain](https://hex.pm/packages/langchain) - ~747k all-time,
  ~179k/month (accessed 2026-07-02).
- [Hex: req_llm](https://hex.pm/packages/req_llm) - ~246k all-time,
  ~173k/month (accessed 2026-07-02).
- [Hex: bumblebee](https://hex.pm/packages/bumblebee) - ~422k all-time
  (accessed 2026-07-02).
- [Hex: nx](https://hex.pm/packages/nx) - ~1.4M all-time (accessed
  2026-07-02).
- [Hex: ex_mcp](https://hex.pm/packages/ex_mcp) - ~3.8k all-time,
  release-candidate status (accessed 2026-07-02).
- [Hex: vancouver](https://hex.pm/packages/vancouver) - pre-0.1 (accessed
  2026-07-02).
- [Hex: mcp_sse](https://hex.pm/packages/mcp_sse)
- [Hex: ortex](https://hex.pm/packages/ortex)
- [Hex: nimble_options](https://hex.pm/packages/nimble_options) - adopted for
  validated config/option schemas (Dashbit-maintained, no transitive deps).
- [Elixir v1.18 released: built-in JSON](https://elixir-lang.org/blog/2024/12/19/elixir-v1-18-0-released/)
- [Elixir JSON module documentation](https://hexdocs.pm/elixir/1.18/JSON.html)
- [Elixir Version requirements: prerelease matching](https://hexdocs.pm/elixir/Version.html)
- [Announcing Elixir OpenChain Certification (2025-02-26)](https://elixir-lang.org/blog/2025/02/26/elixir-openchain-certification/)
- [SEP-1763: Interceptors for Model Context Protocol](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1763)
- [MCP experimental interceptors reference implementation](https://github.com/modelcontextprotocol/experimental-ext-interceptors)
- [MCP Interceptors Working Group charter](https://modelcontextprotocol.io/community/working-groups/interceptors)
- [Tidewave](https://tidewave.ai/)
- [Tidewave MCP setup](https://hexdocs.pm/tidewave/mcp.html)
- [Dashbit: The path to Tidewave](https://dashbit.co/blog/the-path-to-tidewave)
- [protectai/deberta-v3-base-injection-onnx model card](https://huggingface.co/protectai/deberta-v3-base-injection-onnx)
- [meta-llama/Llama-Prompt-Guard-2-86M model card](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)
- [meta-llama/Llama-Prompt-Guard-2-22M model card](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M)
- [Check Point acquires Lakera (press release)](https://www.checkpoint.com/press-releases/check-point-acquires-lakera-to-deliver-end-to-end-ai-security-for-enterprises/)
- [Calcalist: Check Point acquires Lakera in $300 million deal](https://www.calcalistech.com/ctechnews/article/rj5bc1vige) -
  price reported by press, not stated in the vendor release (accessed
  2026-07-02).
- [OpenSSF Best Practices badge](https://www.bestpractices.dev/)
- [OpenTelemetry GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/)
- [GitHub attest-build-provenance action](https://github.com/actions/attest-build-provenance)
- [SLSA v1 specification levels](https://slsa.dev/spec/v1.2/levels)
- [git_ops](https://hexdocs.pm/git_ops/)
- [Livebook](https://livebook.dev/)
- [Elixir Radar](https://elixir-radar.com/)
- [Thinking Elixir podcast](https://podcast.thinkingelixir.com/)
- [ElixirForum](https://elixirforum.com/)
- [ElixirConf](https://elixirconf.com/)
- [awesome-elixir](https://github.com/h4cc/awesome-elixir)
