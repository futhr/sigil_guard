---
sigil_guard:
  id: "R.07"
  topic: "Runtime Dependency Selection, Detection Placement, And Interoperability"
  category: research
  status: complete
  created: "2026-07-02"
  updated: "2026-08-19"
  decision: adopted
  tags:
    [
      "dependencies",
      "interoperability",
      "integrations",
      "adaptive-detection",
      "release-engineering",
      "supply-chain"
    ]
---

# R.07 - Runtime Dependency Selection, Detection Placement, And Interoperability

## Executive Summary

SigilGuard v3 is an embedded security runtime for MCP and agent-tool
boundaries: it mediates a trust boundary in-process rather than at a network
hop. This note records four adopted decisions that follow from that
architectural placement. Core runtime dependencies are kept
minimal and individually justified rather than driven to zero - `:telemetry`,
`:nimble_options`, and a JSON library (Jason) - on an Elixir `~> 1.18` floor
justified by OTP 27 crypto and set-theoretic types (D9); adaptive/ML detection
is a core behaviour with a deterministic nil-path while the model-backed
reference implementation is deferred to an optional post-GA package (D5); v3
ships no compatibility namespace and migrates users through `MIGRATING-1.0.md`
and the changelog only (D6); and the release sequence is a direct manual
alignment to `1.0.0`, followed by git_ops, package, and reference-consumer
validation (D11). It also fixes the prioritised interoperability surface
(hermes_mcp, Jido, LangChain/ReqLLM, Tidewave) and the documentation and
release artifacts that SP.14 and SP.15 turn into tasks.

## Research Question

What dependency posture, adaptive-detection stance, compatibility stance,
interoperability surface, and release sequence should SigilGuard v3 adopt?

Five sub-questions:

1. Which architectural shapes already address agent-boundary security, and
   which properties does an in-process design offer that a network-boundary
   design structurally cannot?
2. Which runtime dependencies does the v3 core keep, on what individual
   merits, and what replaces the ones it drops?
3. Where does ML-backed detection live relative to the deterministic core?
4. Does v3 carry a compatibility namespace for 0.2.x users, or documentation
   only?
5. How do 0.2.x and 1.0.0 coexist on Hex, and which documentation and
   supply-chain artifacts does a security library owe its consumers?

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
- Conflict handling: vendor-published statements are preferred over
  secondary coverage; latency and size figures without vendor benchmarks are
  marked as working estimates.

## Context

V3 moves SigilGuard from a protocol port to a standalone embedded security
runtime. Dependency posture and release mechanics are load-bearing for a
security library: every dependency is an auditable claim that must justify
itself on merit, the migration path is part of the trust model, and the
interoperability surface determines where the gate can be inserted at all. A
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
in SP.12, and the two new specs SP.14 (ecosystem integrations and
interoperability) and SP.15 (benchmarks).

## Findings

### Related Work: Architectural Shapes For Agent-Boundary Security

Prominent cross-language work clusters into three architectural shapes, none
of which runs in-process on the BEAM:

- **Gateway proxies** that sit in front of MCP servers and route traffic
  through a separate process or container.
- **Guardrail model stacks** that pair a policy layer with a classifier model;
  these are Python-native and model-dependent.
- **Scanners and hosted APIs** that expose detection across a network
  boundary, either as a library call into a model or as a remote service.

A survey of the Elixir package index (accessed 2026-07-02) found one
neighbouring package offering scanner-shaped prompt and content checks. It
addresses a different problem — detection, rather than mediation of a trust
boundary with signed material and tamper-evident evidence — so the two are
complementary rather than substitutable.

The design question is therefore not which shape is preferable in general, but
which properties an in-process runtime can offer that a network-boundary
design structurally cannot. Those properties are what the remaining decisions
optimise for:

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

### Tier 1 Interoperability Targets

Prioritised by ecosystem adoption, used as a proxy for how many consumers a
single integration guide serves. Hex download figures accessed 2026-07-02.

| Target | Hex downloads | Extension point | SigilGuard insertion |
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

### Tier 2 Targets (Tracked, No Guides)

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

### Supply-Chain And Observability Alignment

Two ecosystem facts constrain the artifact set a security library should
publish. Elixir itself has been OpenChain ISO/IEC 5230 certified since
2025-02-26 and ships attested source SBOMs (CycloneDX 1.6+/SPDX 2.3+) with its
releases, so a library that publishes SLSA provenance and SBOMs matches the
language's own posture rather than inventing one. On observability, the
OpenTelemetry GenAI semantic conventions (`gen_ai.*`) remain experimental, so
the stable pattern used by Oban, Ecto, and Phoenix applies: keep library-owned
telemetry events as the contract and offer `opentelemetry_api` attribute
mapping as an optional dependency.

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
  doctor, excoveralls, mox, benchee, stream_data, muex, git_ops, and similar)
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

### 2026-08-19 Livebook Delivery Refresh

This implementation refresh checked the current primary HexDocs before
expanding the tutorial suite.

**Facts.** Livebook 0.19 documents package tutorials as a first-class use case
and recommends that a notebook inside a Mix project install the project by
local path while reusing its configuration and lockfile. A Run in Livebook
badge imports one `.livemd` file rather than cloning its repository, so a
local-path-only setup is insufficient for badge users. Livebook exposes a
secret named `OPENAI_API_KEY` to notebook code as `LB_OPENAI_API_KEY`. ReqLLM
1.20 represents proposed tool calls separately from tool execution:
`ReqLLM.Response.tool_calls/1` returns the model's proposals and the host
chooses whether and when to execute them.

**Inference.** The repository tutorials need two dependency paths: the local
checkout path with the repository lock/config for development and the
published `sigil_guard` Hex package for a badge import. A conference AI demo
must not make its security result depend on network access, a provider key, or
the model choosing the expected action. The model is a planner; the host still
owns the tool loop and can put `SigilGuard.ToolGateway` between the proposed
call and its callback.

**Recommendation.** Keep an offline, deterministic replay as the default AI
demo and enable a live ReqLLM proposal only when the Livebook secret is
present. Both paths construct the same MCP-shaped candidate and pass through
the same SigilGuard boundary. The full notebook suite gets a reader-facing
catalog, explicit learning paths, expected outcomes, production caveats, and
speaker cues; every deterministic cell remains executable by
`mix sigil.livebook_check` with network access disabled.

### 2026-08-19 Hex Advisory Refresh

**Facts.** The locked test dependency path `bypass -> plug_cowboy -> cowboy ->
cowlib` resolves Cowlib 2.19.0. Hex currently lists CVE-2026-43966,
CVE-2026-43969, and CVE-2026-43971 for that release. Cowlib is absent from the
production dependency tree, SigilGuard does not call the affected Cowlib
encoders, and Hex has no patched Cowlib release as of 2026-08-19.

**Decision.** These three advisories are explicitly acknowledged as
non-production, unreachable findings, not silently suppressed. The canonical
gate runs both `mix deps.audit` and `mix hex.audit`, so an unreviewed Hex
advisory fails CI. Re-review the exceptions before 2026-09-19 and immediately
before the 1.0.0 release, whichever comes first; remove each exception as soon
as the test dependency path can resolve a fixed Cowlib release.

The same refresh verified the locked production graph's license metadata:
Jason 1.4.5, NimbleOptions 1.1.1, and Telemetry 1.4.2 each declare
`Apache-2.0`. SBOM generation now reads that metadata from the installed,
locked Hex artifacts and fails rather than emitting `NOASSERTION` when runtime
license evidence is absent or version-mismatched.

## Recommendation

**Decision:** adopted.

All four decision areas above are adopted, together with the Tier 1/Tier 2
interoperability tiering, the delivery model, and the artifact set below.
This closes R.01's fourth Deferred item (whether adaptive anomaly detection
belongs in the main package or an optional provider behaviour) and R.01 Open
Questions 4 (compatibility namespace versus `MIGRATING-1.0.md`) and 5
(adaptive scanning as a core behaviour versus a separate package), and it
closes the task-list open decisions on adaptive detectors, the compatibility
namespace, and the release sequence.

**Rationale:** The in-process design occupies a different point in the design
space from the proxy and hosted shapes surveyed above, and the properties it
offers — call-path cost, OTP supervision, deterministic verdicts, local signed
evidence — follow from that placement rather than from feature count. For a
security library, every dependency is a claim that must survive an audit, and
the
defensible posture is minimal and well-justified rather than zero: keep
`telemetry`, adopt `nimble_options` for validated config schemas, keep
`jason`, and drop finch by deleting its only consumer. That is stronger than
a bare dependency count, which forces worse hand-rolled code the moment it is
treated as a goal. Determinism is the architectural commitment, so ML stays
optional and advisory. The download data makes compatibility machinery pure
cost with no beneficiary. And the release sequence is proportionate to the
current install base while protecting rc consumers from the
prerelease-resolution trap.

### Adopted Documentation And Release Artifacts

SP.14 owns acceptance criteria; SP.15 owns benchmark rules.

- ExDoc cheatsheets (`.cheatmd`) covering the gate, policy, and audit APIs.
- Eleven Livebook tutorials with Run in Livebook badges, each executing
  top-to-bottom offline via `Mix.install`, plus a reader catalog with
  self-study, conference-talk, and workshop routes. The AI chapter defaults to
  a deterministic replay and optionally uses a Livebook secret for a ReqLLM
  proposal; both routes pass through the same host-owned boundary gate.
- 100% documentation coverage enforced by `mix doctor`; dialyzer clean.
- Published benchmarks per SP.15, including a scope-limited comparison
  against the Python `llm-guard` scanner suite as a baseline: same corpus,
  versions disclosed, and no claims beyond the shared scanning scope.
- SECURITY.md with a responsible-disclosure process, and the OpenSSF Best
  Practices badge worked through bestpractices.dev.
- Signed releases, SLSA Build L3 provenance via GitHub's
  attest-build-provenance action, and SBOMs from the existing SPDX mix
  task, explicitly aligned with Elixir's own OpenChain-certified,
  SBOM-attested release posture.

Integration delivery: Tier 1 guides (hermes_mcp with the anubis_mcp note,
Jido, LangChain/ReqLLM, and the Tidewave example) ship as ExDoc guides plus
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
  SP.14 (ecosystem integrations and interoperability), new SP.15
  (benchmark methodology and baseline comparison fairness rules).
- Migration needed: yes. `MIGRATING-1.0.md` carries a 1:1 mapping for every
  removal; no runtime compatibility namespace; historical vectors move to
  `test/fixtures/historical/`.
- Breaking changes: yes. Elixir floor 1.17 to 1.18, adoption of
  `nimble_options` and removal of finch from the dependency contract (jason
  stays), deletion of legacy modules, and the major version jump sequenced
  per D11.

## Sources

Hex download figures are post-cutoff observations recorded as accessed
values (accessed 2026-07-02 unless noted).

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
- [OpenSSF Best Practices badge](https://www.bestpractices.dev/)
- [OpenTelemetry GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/)
- [GitHub attest-build-provenance action](https://github.com/actions/attest-build-provenance)
- [SLSA v1.2 build-level requirements](https://slsa.dev/spec/v1.2/build-requirements)
- [git_ops](https://hexdocs.pm/git_ops/)
- [Livebook](https://livebook.dev/)
- [Livebook 0.19: documentation with `Mix.install`](https://livebook.hexdocs.pm/use_cases.html)
- [Livebook 0.19: shared secrets](https://livebook.hexdocs.pm/shared_secrets.html)
- [ReqLLM 1.20: getting started and tool calling](https://req-llm.hexdocs.pm/getting-started-3.html)
- [ReqLLM: canonical tool-call data structures](https://req-llm.hexdocs.pm/data-structures.html)
- [Elixir Radar](https://elixir-radar.com/)
- [Thinking Elixir podcast](https://podcast.thinkingelixir.com/)
- [ElixirForum](https://elixirforum.com/)
- [ElixirConf](https://elixirconf.com/)
- [awesome-elixir](https://github.com/h4cc/awesome-elixir)
