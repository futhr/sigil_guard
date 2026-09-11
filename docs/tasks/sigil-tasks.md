# SigilGuard V3 Tasks

This is the canonical execution checklist for SigilGuard v3, the embedded
Agent Trust Profile runtime. V3 is a deliberate, spec-governed breaking
release: every architectural decision (D1-D21) is closed, research-backed,
and recorded below with rationale (see Closed Decisions); no open choices
remain. Execute milestones strictly in order F -> M0 -> M1 -> ... -> M11. A
task is done only when its AC bullets hold and its named test families
exist. Migration lives in `MIGRATING-1.0.md`, `CHANGELOG.md`, and release
notes - never in permanent legacy runtime shims.

This file, the research notes (`../research/R.01`-`R.10`), and the specs
(`../specs/SP.01`-`SP.18`) are the complete, self-contained plan of record.
An implementer needs nothing outside `docs/` and the codebase. The decisions
were derived from primary-source research and adversarially verified against
those sources; do not reopen a closed decision without a superseding
research note.

## Orientation (Read First)

Historical implementation orientation retained for maintainers reviewing the v3
rewrite. All milestones described below are complete.

**v0.2.x versus v3.** The former `lib/` was the released 0.2.x runtime; v3 was
a deliberate breaking rewrite, not an incremental patch. The Rust/NIF backend
is already gone and stays gone (`CLAUDE.md` rule 1) - ignore any NIF, rustler,
precompiled-binary, or `SIGIL_GUARD_BUILD` references in history. Do not carry
the v0.2 `Registry`, `Envelope`, `Profile`, `protocol_profile`, or
`registry_*` surfaces into v3; they are deleted in M6 with 1:1 migration
mappings in `MIGRATING-1.0.md`. Legacy golden vectors move to
`test/fixtures/historical/` as migration evidence, not v3 proofs.

**The reference consumer contract.** One production agent runtime embeds
SigilGuard (Elixir `~> 1.19`, OTP 27+). Its 1.0 migration remains
maintainer-owned and is validated against the published package. It depends on
the stable contracts in decision **D17**: `scan/1`, `scan_and_redact/1`,
`policy_verdict/3`, the `Identity` / `Signer` / `Vault` behaviours,
`Signer.Ed25519.{new/1, sign_with/2, verify/3}`, and the `%Audit{}` struct
fields - all kept byte-identical in v3 (hit maps extend additively only). The
host supplies three init secrets via config: an audit HMAC key, an Ed25519
signer seed, and a vault master key.
`test/sigil_guard/conformance/consumer_contracts_test.exs` (task M1.02)
encodes these as executable assertions and MUST stay green at every milestone
exit - it is the tier-1 regression gate.

**Naming and privacy.** Never write the private consumer project's name, or
its internal module names, into any repository file (`CLAUDE.md` rule 11).
Refer to it only as "the reference consumer"; neutralize example identifiers
(e.g. `host:operator:42`). Maintain this in every new file.

**Release mechanics.** The repo is aligned directly to `1.0.0` as the major
release line (D11, M8). `git_ops` remains the normal release tool after the
manual major-version alignment is committed and verified with
`mix git_ops.release --dry-run` resuming cleanly. The maintainer performs
publish, push, tag, and production consumer movement manually; consumers move
to `~> 1.0` only after the package is published and validated.

**Gate and conventions.** Canonical gate `./bin/check` (full list in
`CLAUDE.md`); coverage >= 95%; run `mix credo --strict` before each commit.
Security modules need negative/tamper/replay/expiration/malformed tests
(`CLAUDE.md` rule 9). Conventional commits, no AI attribution or co-author
trailers (rule 10); the maintainer pushes manually.

## Progress Summary

**Overall: 281 / 287 tasks done (97.9%).** Milestones: 14 complete, 1 in progress.
**Current milestone: M12 - production boundary hardening.**

| # | Milestone | Done | Total | % | Status |
|----|-----------|-----:|------:|-----:|-------------|
| F  | Completed foundation and research | 30 | 30 | 100% | Complete |
| M0 | Decision lock and docs foundation | 22 | 22 | 100% | Complete |
| M1 | Core groundwork | 19 | 19 | 100% | Complete |
| M2 | Embedded trust bundles | 16 | 16 | 100% | Complete |
| M3 | Manifests, gateway, and agent trust | 22 | 22 | 100% | Complete |
| M4 | Boundary scanner and policy kernel | 25 | 25 | 100% | Complete |
| M5 | Audit, telemetry, provenance, threat suite | 26 | 26 | 100% | Complete |
| M6 | Legacy removal, dep cut, migration gate | 31 | 31 | 100% | Complete |
| M7 | Integrations and adoption | 18 | 18 | 100% | Complete |
| M7A | Pre-release audit hardening | 26 | 26 | 100% | Complete |
| M8 | Release | 8 | 8 | 100% | Complete |
| M9 | MCP `2026-07-28` alignment | 12 | 12 | 100% | Complete |
| M10 | External assessment projection | 1 | 1 | 100% | Complete |
| M11 | Security audit remediation | 22 | 22 | 100% | Complete |
| M12 | Production boundary hardening | 3 | 9 | 33.3% | In progress |
| — | **Total** | **281** | **287** | **97.9%** | 14 done |

### Release Handoff

M9 aligned the unreleased 1.0 gateway, confirmation, manifest, Apps, docs, and
release artifacts with MCP `2026-07-28`.

M10 added an optional, host-context OSCAL Assessment Results v1.2.3
observation projection without changing native audit exports or Agent Trust
statements.

Post-release maintenance includes ongoing dependency-audit remediation,
per-module security coverage review, and periodic regression review of the
implemented policy-loader symlink containment, receipt-URL allowlisting, and
bounded local-anchor log reads. Runtime and anchor-store public boundaries also
maintain malformed option-container campaigns so improper input fails closed
without exceptions. Direct scanner calls reject malformed options explicitly,
policy evaluates them as blocked, and trust-bundle loading classifies them as
invalid sources.

Publish, push, tag, release-checklist execution, and production consumer bumps
are maintainer-owned operations and are intentionally outside this checklist.
After the owner-managed package flow, validate the reference consumer against
the actual 1.0.0 package artifact as release handoff evidence.

The table counts every milestone task (F through M12, including M7A) exactly
once. The
Mandatory Gates section is a recurring pre-commit checklist and the Deferred
section is post-1.0.0 parking; neither is counted here.

## Operating Rules

- Treat v3 as a breaking refactor.
- Keep the package and project name `SigilGuard`.
- Build around the Agent Trust Profile, not the abandoned upstream protocol.
- Keep old SIGIL-shaped logic only as private implementation ancestry or
  historical fixtures where useful.
- Do not keep a public registry runtime path in v3.
- Do not keep compatibility shims just to preserve v2 APIs.
- Put v2-to-v3 migration in `MIGRATING-1.0.md` and `CHANGELOG.md`.
- Keep SigilGuard embedded/local-first; host applications own transport,
  auth, sandbox execution, storage, and deployment.
- Add tests with every behavior change.
- Keep coverage at or above 95%.
- Execute milestones strictly in order; never start a task whose
  milestone's dependencies are not complete, and never mark a milestone
  complete before its exit criteria hold.
- Any commit that changes, renames, or deletes a consumer-facing contract
  MUST update `test/sigil_guard/conformance/consumer_contracts_test.exs`
  and `MIGRATING-1.0.md` in the same commit.
- From M6 exit onward the runtime dependency set is exactly the intended
  minimal set — `:telemetry`, `:nimble_options`, `:jason` — plus OTP/stdlib
  applications; new runtime dependencies require a decision record (D9).

## Mandatory Gates For Every Commit

- [ ] `git diff --check`.
- [ ] Scan for forbidden inspiration-project terms without documenting the
      literal terms in repo text.
- [ ] Scan for dead public protocol/registry URLs without documenting those
      literal URLs in repo text.
- [ ] Scan v3 public docs/examples for old wire/config vocabulary except
      migration docs and historical fixtures.
- [ ] `mix format --check-formatted`.
- [ ] `mix compile --warnings-as-errors`.
- [ ] `mix credo --strict`.
- [ ] `mix sobelow --config --compact`.
- [ ] `./bin/check-secrets`.
- [ ] `mix deps.audit`.
- [ ] `mix hex.audit`.
- [ ] `mix test --cover` with coverage >= 95%.
- [ ] focused verdict mutation gate at 100%.
- [ ] `mix sigil.livebook_check`.
- [ ] `mix doctor`.
- [ ] `mix dialyzer`.
- [ ] `mix docs`.
- [ ] `./bin/check`.

## Milestone F - Completed Foundation And Research

> Anchor: `SP.06`-`SP.11`, `R.01`. Depends on: nothing. Status: complete.

### Foundation Already Built

- [x] F.01 Pure Elixir backend is the supported built-in backend.
- [x] F.02 Rust/NIF backend selection is rejected cleanly.
- [x] F.03 Envelope compatibility profiles and historical golden vectors
      exist.
- [x] F.04 Replay checks exist for nonce-bearing envelopes.
- [x] F.05 MCP gateway request/result guards exist.
- [x] F.06 Streaming sanitizer exists.
- [x] F.07 Staged scanner pipeline foundation exists.
- [x] F.08 Confirmation tokens are bound to action digests.
- [x] F.09 Signed remote-bundle provenance and quarantine foundation exists.
- [x] F.10 OpenTelemetry-style attribute mapping foundation exists.
- [x] F.11 Audit checkpoint/export/anchor foundation exists.
- [x] F.12 SBOM generation and verification task foundation exists.
- [x] F.13 Repo policy kernel foundation exists.

### V3 Research And Specs (First Wave)

- [x] F.14 Add `docs/research/R.01-embedded-mcp-trust-profile.md`.
- [x] F.15 Reframe R.01 around an embedded Agent Trust Profile.
- [x] F.16 Add flat `docs/specs/SP.01` through `SP.12`.
- [x] F.17 Make `SP.01` the v3 Agent Trust Profile spec.
- [x] F.18 Make `SP.02` a local trust-bundle spec with no network core.
- [x] F.19 Make `SP.03` a transport-neutral MCP/tool gateway spec.
- [x] F.20 Make `SP.04` a boundary scanner and deterministic policy spec.
- [x] F.21 Update `SP.07` to describe runtime gate rewiring to
      `BoundaryPolicy`.
- [x] F.22 Update `SP.08` to describe `_agent_trust` and
      `_agent_confirmation`.
- [x] F.23 Update `SP.09` to align current audit chain with v3 evidence
      exports.
- [x] F.24 Update `SP.10` to clarify host identity/vault boundaries for v3.
- [x] F.25 Update `SP.11` to align repo policy with boundary policy facts.

### SP.01 Design Decisions (Locked)

- [x] F.26 Use Agent Trust Profile as the v3 product center.
- [x] F.27 Replace public `_sigil` metadata with `_agent_trust`.
- [x] F.28 Replace public `_sigil_confirmation` metadata with
      `_agent_confirmation`.
- [x] F.29 Use RFC 8785 JCS for external canonical profile bytes.
- [x] F.30 Remove `protocol_profile` config in v3.

## M0 - Decision Lock And Docs Foundation

> Specs: `R.02`-`R.07`, `SP.01`-`SP.15`. Depends on: F.
> Exit criteria: every D1-D18 decision is recorded in exactly one owning
> doc with rationale; `mix docs` renders the full docs tree without
> warnings; relative links across `docs/` resolve; M0.22 lands green.

- [x] M0.01 Research note R.02 - attestation envelope and canonical
      encoding (D1).
  - File: `docs/research/R.02-attestation-envelope-and-canonical-encoding.md`.
- [x] M0.02 Research note R.03 - trust-bundle role model (D3).
  - File: `docs/research/R.03-trust-bundle-role-model.md`.
- [x] M0.03 Research note R.04 - audit proofs, witnessing, privacy
      (D4, D10).
  - File: `docs/research/R.04-audit-proofs-witnessing-and-privacy.md`.
- [x] M0.04 Research note R.05 - actor identity, delegation, A2A (D2).
  - File: `docs/research/R.05-actor-identity-delegation-and-a2a.md`.
- [x] M0.05 Research note R.06 - agentic threat model and control mapping
      (D12; defines test families TM.01-TM.12).
  - File: `docs/research/R.06-agentic-threat-model-and-control-mapping.md`.
- [x] M0.06 Research note R.07 - runtime dependency selection, detection
      placement, and interoperability (D5, D6, D9, D11).
  - File: `docs/research/R.07-runtime-dependencies-and-interoperability.md`.
- [x] M0.07 SP.01 full upgrade: DSSE + JCS normative encoding, statement
      registry, digest computation, golden vectors, v3 config surface,
      shared error taxonomy.
  - File: `docs/specs/SP.01-sigilguard-trust-profile.md`.
- [x] M0.08 SP.02 full upgrade: role model, rotation ceremony, loading
      sources, library-mode bootstrap, reconciled error atoms.
  - File: `docs/specs/SP.02-embedded-trust-bundles.md`.
- [x] M0.09 SP.03 full upgrade: manifest canonical form, confirmation
      lifecycle, threat coverage, JSON-RPC error registry, facade table.
  - File: `docs/specs/SP.03-mcp-attestation-gateway.md`.
- [x] M0.10 SP.04 full upgrade: sandbox identity, policy grammar, output
      contracts, hooks, adaptive behaviour, streaming property spec.
  - File: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md`.
- [x] M0.11 SP.05 full upgrade: proofs, witness cosigning, privacy
      classes, read/query API, OTel namespace, provenance, HTTPClient.
  - File: `docs/specs/SP.05-audit-and-release-provenance.md`.
- [x] M0.12 SP.06-SP.09 upgrades: status fix + known-consumers note +
      historical fixture path (SP.06); unified verdict enum + stability
      guarantees (SP.07); confirmation claims delta + metadata namespace +
      gateway function mapping (SP.08); normative constants (SP.09).
  - Files: `docs/specs/SP.06-envelope-and-native-backend-contracts.md`,
    `SP.07-runtime-gate-and-streaming-contracts.md`,
    `SP.08-mcp-gateway-and-confirmation-contracts.md`,
    `SP.09-audit-chain-and-anchor-contracts.md`.
- [x] M0.13 SP.10-SP.12 upgrades: identity shape + trust mapping + vault
      contract (SP.10); D13 filenames + policy facts (SP.11); removal map +
      dependency removal + release sequence (SP.12).
  - Files: `docs/specs/SP.10-vault-and-identity-contracts.md`,
    `SP.11-repo-policy-kernel-contracts.md`,
    `SP.12-legacy-remote-bundle-adapter-contracts.md`.
- [x] M0.14 Create SP.13 - agent-to-agent trust statements.
  - File: `docs/specs/SP.13-agent-to-agent-trust-statements.md`.
- [x] M0.15 Create SP.14 - ecosystem integrations and interoperability.
  - File: `docs/specs/SP.14-ecosystem-integrations-and-interoperability.md`.
- [x] M0.16 Create SP.15 - benchmark methodology and baselines.
  - File: `docs/specs/SP.15-benchmark-methodology-and-baselines.md`.
- [x] M0.17 R.01 surgical edits (deferred items and open questions resolved
      to R.NN pointers) plus `docs/research/README.md` index update.
- [x] M0.18 `docs/README.md` and `docs/specs/README.md` updated with
      SP.13-SP.15 and R.02-R.07 rows, diagrams, ownership rules.
- [x] M0.19 CLAUDE.md reconciliation: rules 3/4 restated for the
      spec-governed v3 break; architecture section updated.
- [x] M0.20 Root README status/roadmap block (0.2.x current, v1.0 planned
      breaking release) plus legacy trust-bundle bullet disambiguation.
- [x] M0.21 Rewrite `docs/tasks/sigil-tasks.md` as this v3 checklist.
- [x] M0.22 Add `mix sigil.docs_lint` dev task.
  - Spec: `docs/specs/README.md` (catalogue rules); this file, Mandatory
    Gates.
  - AC: one mix task consolidates the doc checks: spec-drift check (every
    `SP.NN` has a task block here and vice versa), forbidden
    inspiration-project term scan, dead public protocol/registry URL scan,
    stale three-digit R/SP id scan, local-filesystem link scan, and old
    wire/config vocabulary scan (migration docs and
    `test/fixtures/historical/` exempt).
  - AC: exits non-zero on any finding; forbidden terms and dead URLs live
    in the task's private pattern list, never in repo prose.
  - Tests: fixture-driven task test per check class (positive and clean
    runs); negative (exempt paths do not trip).

## M1 - Core Groundwork

> Specs: `SP.01`; `SP.12` (Dependency Removal); `SP.13` (predicates).
> Depends on: M0.
> Exit criteria: `./bin/check` clean; conformance module (M1.02)
> green (tier-1 gate, required at every later milestone exit too); golden
> vectors committed for all eight statement types; `:nimble_options`
> adopted and validating the config surface.

- [x] M1.01 Raise the Elixir floor to `~> 1.18`.
  - Spec: `docs/specs/SP.01-sigilguard-trust-profile.md` - V3 Configuration
    Surface; `docs/specs/SP.12-legacy-remote-bundle-adapter-contracts.md` -
    Dependency Removal (D9).
  - AC: `mix.exs` declares `elixir: "~> 1.18"`; the CI matrix floor row is
    Elixir 1.18 and compiles green; README requirements match.
  - Tests: full suite green on the 1.18 floor row in CI.
- [x] M1.02 Consumer-contracts conformance module (tier-1 gate).
  - Spec: `docs/specs/SP.07-runtime-gate-and-streaming-contracts.md` -
    Stability Guarantees (D17).
  - AC: `test/sigil_guard/conformance/consumer_contracts_test.exs` encodes
    the D17 contracts as executable assertions: `scan/1` returns
    `{:ok, text} | {:hit, hits}` with `%{name: _}` hit maps;
    `scan_and_redact/1` returns a binary; `policy_verdict/3` returns only
    `:allowed | :blocked | {:confirm, reason}` under a StreamData property
    matrix sweeping all three argument dimensions; the `%SigilGuard.Audit{}`
    field set is asserted literally.
  - AC: ships reference implementations of the `SigilGuard.Identity`,
    `SigilGuard.Signer`, and `SigilGuard.Vault` behaviours shaped like the
    reference consumer's integrations (an actor-pattern trust mapper, a
    request-signing signer, a database-backed vault) that compile and pass
    against the behaviours; Ed25519 golden vectors pin
    `Signer.Ed25519.new/1`, `sign_with/2`, and `verify/3` byte-exactly.
  - AC: this module MUST be green at every milestone exit from M1 onward
    and MUST change in the same commit as any contract change.
  - Tests: property (verdict matrix), golden vectors (Ed25519), negative
    (foreign verdict/hit shapes fail).
- [x] M1.03 Adopt `:nimble_options` for config/option validation; keep
    `:jason`.
  - Spec: `docs/specs/SP.12-legacy-remote-bundle-adapter-contracts.md` -
    Dependency Removal (D9); `docs/specs/SP.01-sigilguard-trust-profile.md`
    - V3 Configuration Surface.
  - AC: `{:nimble_options, "~> 1.1"}` added to `mix.exs`; the v3 config and
    public-function option surfaces validate through NimbleOptions schemas
    (not hand-rolled), with generated docs; `:jason` STAYS (the earlier
    Jason→stdlib-JSON swap is cancelled per D9 — dep-count is not a goal);
    Elixir floor `~> 1.18` re-justified on OTP 27 + set-theoretic types.
  - Tests: schema-validation negative tests (unknown key, bad value type,
    out-of-range) return typed errors that name `MIGRATING-1.0.md` for
    removed keys.
- [x] M1.04 `SigilGuard.Canonical.JCS` encoder (RFC 8785, ~200 LOC).
  - Spec: `docs/specs/SP.01-sigilguard-trust-profile.md` - JCS Constraints
    (Normative); Public API Sketch.
  - AC: `lib/sigil_guard/canonical/jcs.ex` implements `encode/1` with
    ECMAScript number serialization, UTF-16 code-unit key sort, and no
    unicode normalization; RFC 8785 appendix vectors pass byte-exactly.
  - AC: integers outside +/-(2^53 - 1) return
    `{:error, :unsupported_number_range}`; non-JSON-representable terms and
    post-normalization key collisions return `{:error, :invalid_map}`.
  - Tests: golden vectors (RFC 8785 appendix), negative, malformed.
- [x] M1.05 JCS property tests and adversarial corpus.
  - Spec: `docs/specs/SP.01-sigilguard-trust-profile.md` - JCS Constraints
    (Normative); `docs/research/R.02-attestation-envelope-and-canonical-encoding.md`
    (JCS pitfalls).
  - AC: StreamData properties prove deterministic output (equal maps yield
    identical bytes) and UTF-16 code-unit sort order on adversarial keys
    (astral-plane and surrogate-order cases); the R.02 adversarial corpus
    is committed as fixtures and passes.
  - Tests: property, golden vectors, malformed.
- [x] M1.06 DSSE envelope encode/decode with PAE and multi-signature.
  - Spec: `docs/specs/SP.01-sigilguard-trust-profile.md` - Attestation
    Envelope And Canonical Encoding (DSSE Envelope; Pre-Authentication
    Encoding (PAE)).
  - AC: `lib/sigil_guard/attestation/envelope.ex` implements
    `{payload, payloadType, signatures: [{keyid, sig}]}` with payloadType
    `application/vnd.sigilguard+json` and the exact PAE bytes
    `"DSSEv1" SP len(type) SP type SP len(body) SP body`.
  - AC: multi-signature envelopes verify; duplicate keyids fail
    `:duplicate_keyid`; undecodable base64url fails `:invalid_base64`;
    wrong payloadType fails `:invalid_payload_type`; non-map/badly typed
    envelopes fail `:invalid_envelope`.
  - Tests: negative, tamper (flipped payload byte -> `:invalid_signature`),
    malformed.
- [x] M1.07 Statement builder.
  - Spec: `docs/specs/SP.01-sigilguard-trust-profile.md` - Statement Shape;
    Public API Sketch.
  - AC: `lib/sigil_guard/attestation/statement.ex` builds and parses
    in-toto Statements (`_type` = `https://in-toto.io/Statement/v1`) with
    fixed subject order `action`, `payload`, `context`, `manifest`
    (manifest present only when applicable).
  - AC: subject name/order violations fail `:invalid_profile`.
  - Tests: negative, malformed, golden vectors.
- [x] M1.08 `SigilGuard.TrustProfile` registry, eight statement types, and
      structural validation.
  - Spec: `docs/specs/SP.01-sigilguard-trust-profile.md` - Statement Type
    Registry; Public API Sketch.
  - AC: `profile_id/0` returns `"sigil_guard_agent_trust/v1"`;
    `statement_types/0` returns, in fixed order, `:tool_request`,
    `:tool_result`, `:model_ingress`, `:model_egress`, `:repo_change`,
    `:release`, `:agent_request`, `:agent_response`; `predicate_type/1` is
    a closed map to `https://sigilguard.dev/attestation/<type>/v1` URIs.
  - AC: `validate/1` performs the structural checks; unregistered
    predicateType fails `:unknown_statement_type`; a non-`v1` profile
    version fails `:unsupported_profile_version`; no `String.to_atom/1` on
    external input anywhere in the dispatch path.
  - Tests: negative, malformed.
- [x] M1.09 A2A predicate extension fields for `agent_request` and
      `agent_response`.
  - Spec: `docs/specs/SP.13-agent-to-agent-trust-statements.md` - Agent
    Request And Agent Response Predicates;
    `docs/specs/SP.01-sigilguard-trust-profile.md` - Digest Computation
    (Normative).
  - AC: `agent_request` carries `peer_agent`, `peer_trust`, `capability`,
    and optional opaque `delegation_chain` (hop maps with required
    `"actor"` and optional `"evidence"` only; explicit empty list fails
    `:invalid_payload`); `agent_response` adds `request_action_digest`,
    `status` (`ok`/`error` only), and `quarantined`; `tool` absent in both.
  - AC: action digests follow the SP.01 rows; delegation-chain order is
    digest-bound - any hop reorder, insert, drop, or edit changes the
    payload digest.
  - Tests: negative, tamper, malformed.
- [x] M1.10 `_agent_trust`/`_agent_confirmation` metadata helpers with
      collision rules.
  - Spec: `docs/specs/SP.01-sigilguard-trust-profile.md` - Metadata Strip
    Rule; Public API Sketch (attach/fetch);
    `docs/specs/SP.08-mcp-gateway-and-confirmation-contracts.md` -
    Metadata Namespace.
  - AC: `Attestation.attach/2`, `fetch/1`, `attach_confirmation/2`, and
    `fetch_confirmation/1` read/write `_agent_trust` and
    `_agent_confirmation` under atom or string keys; `attach/2` raises
    `ArgumentError` on non-map payloads; `fetch/1` returns `:error` when
    the key is absent or not a map.
  - AC: the digest strip rule removes exactly the six keys
    (`_agent_trust`, `_agent_confirmation`, `confirmation_token`, atom and
    string forms) at payload top level and under `params`; digests are
    byte-identical with and without them, including mixed atom+string
    collisions.
  - Tests: negative, malformed, property (strip invariance).
- [x] M1.11 Digest computation module.
  - Spec: `docs/specs/SP.01-sigilguard-trust-profile.md` - Digest
    Computation (Normative) (Normalization Rules; Context Digest; Payload
    Digest; Action Digest; Manifest Digest (Applicability)).
  - AC: `lib/sigil_guard/attestation/digest.ex` implements normalization
    (atoms to strings, omit absent/nil optionals, never emit `null`) and
    the exact per-type action-digest field lists for all eight statement
    types; the context digest includes `sandbox_id` and `isolation_level`;
    all digests are lowercase-hex SHA-256 over compact JCS bytes.
  - Tests: golden vectors, negative, malformed.
- [x] M1.12 `Attestation.sign/3` and `Attestation.verify/3`.
  - Spec: `docs/specs/SP.01-sigilguard-trust-profile.md` - Public API
    Sketch; Error Handling.
  - AC: `sign/3` uses `SigilGuard.Signer`, defaults keyid to the derived
    `"sha256:" <> hex` form, and accepts `:now`/`:nonce` for deterministic
    tests; `verify/3` follows the normative order (envelope structure,
    payloadType, base64, duplicate keyid, `:expected_payload_sha256`, keyid
    resolution, Ed25519 over PAE, Statement parse, `TrustProfile.validate/1`,
    digest recomputation, freshness, replay).
  - AC: empty trust material fails `:missing_trust_bundle`; no resolvable
    keyid fails `:unknown_key_id`; a resolved-but-invalid signature fails
    `:invalid_signature`; unresolved keyids are tolerated (witness
    cosigning support).
  - Tests: negative, tamper, replay, expiration, malformed.
- [x] M1.13 `Attestation.from_decision/3`.
  - Spec: `docs/specs/SP.01-sigilguard-trust-profile.md` - Public API
    Sketch (from_decision/3).
  - AC: phase-to-type closed map (`:inbound_user -> :model_ingress`,
    `:tool_request`, `:tool_result`, `:outbound_model -> :model_egress`,
    `:repo_change`); `:release`, `:agent_request`, and `:agent_response`
    require the explicit `:statement_type` option, which always wins;
    actor resolves `context.actor` then `context.identity`, both absent
    fails `:invalid_payload`.
  - Tests: negative, malformed.
- [x] M1.14 Golden vectors for all eight statement types.
  - Spec: `docs/specs/SP.01-sigilguard-trust-profile.md` - Canonical
    Example And Golden Vectors; Fixture File Set.
  - AC: a deterministic generator emits
    `test/fixtures/agent_trust/<type>/{statement,envelope,expected}.json`
    for all eight types from the fixed inputs (Ed25519 seed bytes
    `0x01..0x20`, `issued_at` `2026-07-02T12:00:00.000Z`, +300 s expiry,
    nonce `000102030405060708090a0b0c0d0e0f`); regeneration is
    byte-identical.
  - AC: the `tool_request` vector reproduces the spec's worked example,
    including the manifest digest of the SP.03 `repo_file_write` fixture.
  - Tests: golden vectors (byte-identity round trips for every type).
- [x] M1.15 Replay and expiry semantics for attestations.
  - Spec: `docs/specs/SP.01-sigilguard-trust-profile.md` - Replay And
    Expiry Semantics.
  - AC: defaults `attestation_ttl_ms: 300_000`, `max_skew_ms: 60_000`,
    `replay_ttl_ms: 300_000`; replay scope is `{actor, nonce}` on
    `SigilGuard.ReplayStore`.
  - AC: nonce reuse fails `:replay_detected`; `now > expires_at + skew`
    or `issued_at > now + skew` fails `:expired_attestation`.
  - Tests: replay, expiration (skew boundary +/- 1 ms cases).
- [x] M1.16 Digest tamper matrix tests.
  - Spec: `docs/specs/SP.01-sigilguard-trust-profile.md` - Error Handling;
    Acceptance Criteria.
  - AC: mutating the guarded payload, context, or action inputs each fails
    `:digest_mismatch` (three classes); a mutated manifest fails
    `:manifest_digest_mismatch`.
  - Tests: tamper (all four digest classes).
- [x] M1.17 Malformed-envelope and malformed-statement negatives.
  - Spec: `docs/specs/SP.01-sigilguard-trust-profile.md` - Error Handling.
  - AC: fuzz-style malformed inputs (non-map envelope, non-string
    payloadType, empty or mistyped `signatures`, truncated base64,
    non-Statement JSON payloads) return taxonomy atoms and never raise.
  - Tests: malformed, negative.
- [x] M1.18 SP.01 error-taxonomy coverage assertion.
  - Spec: `docs/specs/SP.01-sigilguard-trust-profile.md` - Error Handling;
    Acceptance Criteria.
  - AC: a test enumerates every SP.01 taxonomy atom and asserts each is
    produced by at least one test in the suite.
  - Tests: negative (meta-assertion over the ledger).
- [x] M1.19 Coverage trend gate in CI.
  - Spec: this file - Mandatory Gates For Every Commit.
  - AC: CI fails whenever `mix test --cover` reports below 95%; the
    threshold lives in the coverage tool configuration, not an ad hoc
    grep.
  - Tests: synthetic below-threshold run demonstrates the failure path.

## M2 - Embedded Trust Bundles

> Specs: `SP.02`. Depends on: M1 (JCS/DSSE from M1.04-M1.06).
> Exit criteria: `./bin/check` clean; M1.02 conformance green;
> negative verification matrix green; no-network test green for all source
> classes and `dev_bundle/1`.

- [x] M2.01 `SigilGuard.TrustBundle` public module.
  - Spec: `docs/specs/SP.02-embedded-trust-bundles.md` - Public API Sketch.
  - AC: `load/1,2`, `verify/2`, `dev_bundle/1`, and section accessors
    `patterns/1`, `policies/1`, `tools/1`, `identity_issuers/1` (empty list
    when absent) exist with the spec's `@spec`s and struct fields
    (`bundle_id`, `sequence`, `root_version`, `digest`, `document`,
    `envelope`, `dev?`, `source`).
  - Tests: golden vectors, negative.
- [x] M2.02 `TrustBundle.Schema` document validation over shared JCS/DSSE.
  - Spec: `docs/specs/SP.02-embedded-trust-bundles.md` - Data Model;
    Signing And Canonical Form.
  - AC: bundle and rotation documents validate against the schema; no
    bundle-local canonicalization exists - all canonical bytes go through
    `SigilGuard.Canonical.JCS` and the M1 DSSE envelope.
  - AC: every `:invalid_bundle_format` trigger class in the spec's Error
    Handling table (regex violations, `rollback_floor > sequence`,
    threshold outside `1..n`, keyid not the SHA-256 of its key, non-32-byte
    keys, unknown top-level fields) rejects with that atom.
  - Tests: malformed (one fixture per trigger class), negative.
- [x] M2.03 `TrustBundle.Verify` pipeline: roles, thresholds, expiry,
      revocations.
  - Spec: `docs/specs/SP.02-embedded-trust-bundles.md` - Role Model And
    Thresholds.
  - AC: a document without a `"bundle"` delegate fails `:unknown_role`;
    v1 enforces effective threshold 1 by default and
    `enforce_declared_threshold: true` raises it to declared m
    (`:threshold_not_met` below m); expired roles fail `:role_expired` and
    document expiry/future-dating fail `:bundle_expired` at skew bounds.
  - AC: revoked keyids are struck from every role before threshold
    counting and fail `:revoked_key` when used.
  - Tests: negative, tamper, expiration, malformed.
- [x] M2.04 `TrustBundle.Cache` ETS snapshot with floor semantics.
  - Spec: `docs/specs/SP.02-embedded-trust-bundles.md` - Public API Sketch
    (Cache).
  - AC: ETS table `:sigil_guard_trust_bundle` is owned by
    `SigilGuard.Runtime`, automatically by default or caller-supervised after
    opt-out; `put/1` accepts only sequence strictly above
    the cached one and at or above the floor, treats a byte-identical
    re-put as a no-op, and advances the floor to
    `max(floor, rollback_floor, sequence)`; `floor/1` returns 0 for
    unknown bundle ids.
  - Tests: negative (`:sequence_below_floor`), replay (duplicate sequence,
    different digest), property (floor monotonicity).
- [x] M2.05 `TrustBundle.Quarantine` failure records.
  - Spec: `docs/specs/SP.02-embedded-trust-bundles.md` - Public API Sketch
    (Quarantine).
  - AC: every load/verify failure writes a record with `reason`,
    `bundle_id`, `bundle_digest` (nil when payload undecodable),
    `sequence`, ISO 8601 UTC ms `quarantined_at`, and SP.01-shaped
    `evidence` refs; `list/0,1` filters by bundle id.
  - Tests: negative (one record per failure class), malformed.
- [x] M2.06 Four loading sources plus `:invalid_source`.
  - Spec: `docs/specs/SP.02-embedded-trust-bundles.md` - Loading Sources.
  - AC: `{:file, path}`, `{:priv, app, rel}`, `{:map, map}`, and
    `{:binary, bin}` load and verify; `:none`, unreadable files/resources,
    non-JSON binaries, and unrecognized constructors fail
    `{:error, :invalid_source}` before verification; exactly one source
    per call, no merging; an explicit source wins over configuration.
  - Tests: negative, malformed (per source class).
- [x] M2.07 Boot wiring for the `:trust_bundle` config key.
  - Spec: `docs/specs/SP.02-embedded-trust-bundles.md` - Loading Sources
    (Precedence); `docs/specs/SP.01-sigilguard-trust-profile.md` - V3
    Configuration Surface.
  - AC: when `:trust_bundle` is not `:none`, boot loads and caches it; any
    failure raises `SigilGuard.ConfigError` naming the verify error atom
    (fail closed).
  - Tests: negative (boot failure per error class), malformed.
- [x] M2.08 Trust-bundle golden fixtures and digests.
  - Spec: `docs/specs/SP.02-embedded-trust-bundles.md` - Canonical Example
    And Golden Vectors.
  - AC: `test/fixtures/trust_bundle/` carries `minimal`, `multisig`, and
    `rotation` fixtures that verify and regenerate byte-identically;
    `bundle_digest` values are asserted against recomputation.
  - Tests: golden vectors.
- [x] M2.09 Negative verification matrix.
  - Spec: `docs/specs/SP.02-embedded-trust-bundles.md` - Testing Strategy;
    Error Handling.
  - AC: malformed, expired, threshold, unknown-role, unknown-key, revoked,
    and tamper cases each produce their named atom (flipped payload byte
    fails `:invalid_signature`; SP.01 shared atoms are reused, never
    redefined); every SP.02 error atom is produced by at least one test.
  - Tests: negative, tamper, expiration, malformed.
- [x] M2.10 Rollback and floor tests.
  - Spec: `docs/specs/SP.02-embedded-trust-bundles.md` - Role Model And
    Thresholds (Monotonic sequence and rollback floor).
  - AC: lower sequence, duplicate sequence with a different digest, and
    root version below the accepted one each fail `:sequence_below_floor`;
    the byte-identical re-put no-op is proven.
  - Tests: replay, negative.
- [x] M2.11 Root-rotation chain walk from the pinned genesis root.
  - Spec: `docs/specs/SP.02-embedded-trust-bundles.md` - Emergency Rotation
    Ceremony (Chain walk; Pinning).
  - AC: verification walks `rotation_chain` in strictly ascending
    `root_version` (each exactly previous + 1) from the pin to a terminal
    descriptor equal to `roles.root`; each rotation document carries the
    full declared old-root AND new-root quorums even under v1 threshold-1
    enforcement, else `:rotation_below_threshold`.
  - AC: an explicit `:genesis_root` option wins over the cached pin; with
    neither, the first verified bundle establishes the pin and per-version
    chain digests; historical chain entries skip expiry checks.
  - Tests: golden vectors (rotation fixture), negative, tamper.
- [x] M2.12 Forked-chain and rotation-replay rejection.
  - Spec: `docs/specs/SP.02-embedded-trust-bundles.md` - Emergency Rotation
    Ceremony (Forks; Rotation replay).
  - AC: two distinct rotation documents for one root version fail
    `:forked_root_chain`, both in-chain and against the cached accepted
    digest; every pre-rotation bundle fails `:sequence_below_floor` after
    the ceremony's floor bump.
  - Tests: tamper, replay, negative.
- [x] M2.13 Signer-compromise helpers: immediate revocation and emergency
      floor bump.
  - Spec: `docs/specs/SP.02-embedded-trust-bundles.md` - Role Model And
    Thresholds (Revocation by list and by omission); Emergency Rotation
    Ceremony.
  - AC: an explicit `revocations` entry kills a keyid mid-cycle regardless
    of unexpired signatures; the cached revocation union is irreversible
    within a boot (revoked keys stay dead after the revoking bundle is
    replaced); omission from the next root document removes authority.
  - AC: the six-step ceremony is exercised end-to-end in one test:
    revoke, cross-signed new root, floor bump above every old sequence.
  - Tests: negative, tamper, replay.
- [x] M2.14 `dev_bundle/1` library-mode bootstrap with doctest.
  - Spec: `docs/specs/SP.02-embedded-trust-bundles.md` - Library-Mode
    Bootstrap.
  - AC: `dev_bundle/1` (opts `:patterns`, `:policies`, `:tools`,
    `:identity_issuers`, `:seed`, `:now`, `:ttl_ms` default `3_600_000`)
    generates, signs, verifies, and caches a minimal bundle; the result is
    marked dev everywhere: provenance `issuer_class: "dev"`, struct
    `dev?: true` and `source: :dev`, telemetry `dev: true`.
  - AC: a doctest on `dev_bundle/1` demonstrates the bootstrap; no
    production doc or config example references it.
  - Tests: doctest, expiration (`:ttl_ms`), negative.
- [x] M2.15 No-network guarantee tests.
  - Spec: `docs/specs/SP.02-embedded-trust-bundles.md` - Loading Sources
    (No-network guarantee).
  - AC: `Port.list()` is unchanged across `load` and `verify` for all four
    source classes and `dev_bundle/1`; the trust-bundle code path
    references no HTTP or socket module (`:httpc`, `:gen_tcp`, `:ssl`,
    `SigilGuard.HTTPClient`).
  - Tests: negative (port-list assertion per source class), static
    reference scan test.
- [x] M2.16 `[:sigil_guard, :trust_bundle, ...]` telemetry events.
  - Spec: `docs/specs/SP.02-embedded-trust-bundles.md` - Telemetry And
    Observability.
  - AC: `:load` and `:verify` spans plus the `:quarantine` event fire with
    the documented metadata; metadata never carries key material or
    section bodies; the new path emits no legacy
    `[:sigil_guard, :registry, ...]` events (rename carried from the v2
    plan).
  - Tests: telemetry assertions per event family, negative (redaction).

## M3 - Manifests, Gateway, And Agent Trust

> Specs: `SP.03`, `SP.08`, `SP.13`. Depends on: M1, M2.
> Exit criteria: `./bin/check` clean; M1.02 conformance green;
> facade parity table green; manifest drift matrix green; agent-card
> golden vectors committed.

- [x] M1.01 `SigilGuard.CapabilityManifest` canonical form.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - CapabilityManifest
    Canonical Form (Digest Field List (Normative)).
  - AC: `new/1` validates the closed field table (required fields, closed
    enums `input_sensitivity`/`output_sensitivity`/`network_access`/
    `reversibility`/`side_effects`, sorted lists, `sandbox` map shape) and
    fails `:invalid_manifest` otherwise; `manifest_format` is
    `sigil_guard_capability_manifest/v2`.
  - Tests: negative, malformed.
- [x] M1.02 Manifest digest, inner digests, and the `repo_file_write`
      golden fixture.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - CapabilityManifest
    Canonical Form (Canonical Example).
  - AC: `digest/1` computes lowercase-hex SHA-256 over compact JCS preimage
    bytes; `description_sha256` hashes raw UTF-8 bytes;
    `input_schema_sha256`/`output_schema_sha256` hash JCS bytes of the
    schema documents; carried `*_sha256` mismatches fail
    `:invalid_manifest`.
  - AC: `test/fixtures/capability_manifest/repo_file_write.manifest.json`,
    `repo_file_write.preimage.json`, and `repo_file_write.expected.json` are
    committed, and the digest equals the value referenced by the SP.01
    `tool_request` golden vector (M1.14).
  - Tests: golden vectors, tamper, malformed.
- [x] M1.03 Suspicious required parameters (schema-injection indicators).
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - Suspicious
    Required Parameters.
  - AC: `suspicious_params` is recomputed deterministically from the
    carried schema using only the built-in `suspicious-params-v1` set
    (walk every `"required"` list at any depth; lowercase, `-` to `_`,
    substring match); a lying manifest fails
    `:suspicious_required_param`.
  - AC: a matching, non-empty disclosure forces `{:confirm, _}` at
    `guard_request` unless boundary policy explicitly allows it; the field
    is bound inside the signed manifest digest.
  - Tests: negative, tamper, malformed.
- [x] M1.04 `ToolGateway.guard_request/3` with the normative check order.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - Public API
    Sketch.
  - AC: the seven-step order holds and the first failing step denies:
    strip+digest, manifest resolution/verification, passthrough/resource/
    audience checks, sandbox requirement, inbound attestation per
    `:attestation`, runtime gate evaluation, confirmation application.
  - AC: documented opts (`:manifests` | `:trust_bundle`,
    `:require_manifest`, `:attestation`, `:confirmation`,
    `:confirmation_key`, `:consume_confirmation`, `:audience`, `:resource`,
    `:self_resource`, `:now`, `:max_skew_ms`) behave per spec; denials are
    block decisions carrying the deny atom in reason and audit_metadata.
  - Tests: negative (per step), tamper, malformed.
- [x] M1.05 `ToolGateway.guard_result/3` with result binding.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - Request And
    Result Attestation Binding (tool_result Binding).
  - AC: `guard_result/3` accepts `:request_action_digest` and binds the
    result to it; quarantine status and scanner summary flow into the
    decision; `guarded_request/3`/`guarded_result/3` and the stream trio
    keep their v2 wire shapes.
  - Tests: negative, tamper, malformed.
- [x] M1.06 `verify_manifest/2` at `tools/list` time (line-jumping
      defense).
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - Public API Sketch
    (verify_manifest/2); Threat Coverage And Host-Owned Exclusions (TM.03).
  - AC: one `tools/list` entry (string keys `"name"`, `"description"`,
    `"inputSchema"`, `"outputSchema"`, `"annotations"`; snake_case twins
    accepted) verifies against pinned manifests or a trust bundle BEFORE
    any definition enters model context or any invocation runs; `:server`
    is required; unknown tools fail `:unknown_manifest`, expired manifests
    `:manifest_expired`.
  - Tests: negative, tamper, expiration, malformed.
- [x] M1.07 `notifications/tools/list_changed` re-verification and approval invalidation.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - Threat Coverage
    And Host-Owned Exclusions (TM.05, TM.07).
  - AC: a `list_changed` notification forces full re-verification; cached
    approvals die with the manifest because confirmation tokens bind
    `manifest_digest` - a re-listed drifted manifest invalidates every
    outstanding token for that tool.
  - Tests: negative, replay (stale approval after re-list), tamper.
- [x] M1.08 Manifest drift matrix tests.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - Acceptance
    Criteria.
  - AC: changed name, description, annotations, permissions/scopes, input
    schema, and output schema are each rejected with their named atom
    (`:manifest_digest_mismatch` or `:schema_digest_mismatch`); none falls
    through to a generic error.
  - Tests: tamper (per field), negative.
- [x] M1.09 `attest_request/3` and `attest_result/3` binding helpers.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - Request And
    Result Attestation Binding; Public API Sketch.
  - AC: `attest_request/3` binds actor, tool/manifest digest, action
    digest, payload digest, context digest, resource, scopes, nonce, and
    expiry via `Attestation.from_decision/3` plus `Attestation.sign/3`;
    `attest_result/3` additionally requires `:request_action_digest`
    (absent fails `:invalid_payload`) and binds result digest, output
    schema digest, sink, quarantine status, and evidence refs.
  - Tests: negative, tamper, malformed.
- [x] M3.10 Confirmation v2 token format.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - Confirmation
    Lifecycle (Claims (v2 Token Format); Defaults And Rules).
  - AC: token = base64url(JCS claims) <> "." <> base64url(HMAC-SHA256 over
    the same JCS bytes); claims carry `v`/`typ`/`alg`, actor, the four
    digests (`action_digest`, `payload_digest`, `context_digest` -
    `sandbox_id` and `isolation_level` live inside it - and
    `manifest_digest` when a manifest applies), decision/action/reason,
    `issued_at`/`expires_at`, 16-byte hex nonce.
  - AC: TTL defaults to `300_000` ms via `:ttl_ms` (no app-env key);
    single-use by default through `SigilGuard.ReplayStore` key
    `"confirmation:" <> actor` (second verification fails
    `:replay_detected`; `consume: false` for stateless checks).
  - Tests: negative, tamper, replay, expiration, malformed.
- [x] M3.11 `issue_confirmation/5` and the multi-step approval flow.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - Confirmation
    Lifecycle (Multi-Step Approval Flow).
  - AC: the six-step flow works end to end: `{:confirm, reason}` decision,
    token issue (direction `:request` or `:result`), re-submit with the
    token under `_agent_confirmation`, verify-and-consume upgrade to
    allowed; confirmed quarantined results release only sanitized text.
  - AC: issue errors are typed (`:invalid_key`, `:not_confirmable`,
    `:invalid_ttl`, `:invalid_actor`, `:invalid_nonce`, `:invalid_now`,
    `:invalid_payload`).
  - Tests: negative, replay, expiration.
- [x] M3.12 Transition dual-strip of `_sigil*` alongside `_agent_*`.
  - Spec: `docs/specs/SP.08-mcp-gateway-and-confirmation-contracts.md` -
    Metadata Namespace; `docs/specs/SP.03-mcp-attestation-gateway.md` -
    Implementation Roadmap (M3).
  - AC: during M3-M5 the gateway reads and strips both `_agent_trust`/
    `_agent_confirmation` and legacy `_sigil`/`_sigil_confirmation`
    (mixed-traffic transition); digests are identical whichever namespace
    carries the metadata; `_agent_*` is the only documented public form.
  - AC: the legacy read half is deleted in M6.25 (tracked there).
  - Tests: property (digest equality across namespaces), negative.
- [x] M3.13 `SigilGuard.MCP.Gateway` rewired as the permanent facade (D14).
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - MCP.Gateway
    Facade (D14).
  - AC: all twenty facade helpers delegate exactly per the spec table
    (confirmation/attestation opt combinations) with identical return
    shapes; parity tests cover every row.
  - Tests: parity suite (facade vs `ToolGateway`), negative.
- [x] M3.14 JSON-RPC error registry, finalized as `-31990..-31984` by D20.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - JSON-RPC Error
    Registry.
  - AC: v3 renumbers gateway rejection codes from v0.2's `-32001..-32003`
    to `-31990` (`blocked`), `-31989` (`confirmation_required`), `-31988`
    (`quarantined`), `-31987` (`manifest_drift` with `drifted_fields`),
    `-31986` (`unknown_manifest`/`manifest_expired`), `-31985`
    (`invalid_attestation` with the SP.01 atom as string), `-31984`
    (`sandbox_required` with isolation fields); each emits exactly the
    documented `data` shape with nil fields omitted; the v0.2 → v3 code
    change is recorded in `MIGRATING-1.0.md`.
  - Tests: negative (per code), golden shape assertions.
- [x] M3.15 Passthrough, audience, and resource denials.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - Public API Sketch
    (check order step 3); Threat Coverage And Host-Owned Exclusions
    (TM.06, TM.07).
  - AC: `opts[:audience] == opts[:self_resource]` fails
    `:token_passthrough_denied`; `:resource` differing from manifest
    `server` fails `:resource_mismatch`; an audience matching neither the
    manifest `server` nor any `audience` entry fails `:audience_mismatch`;
    each maps to its documented JSON-RPC code.
  - Tests: negative, tamper.
- [x] M3.16 Sandbox-required denial for privileged tools.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - CapabilityManifest
    Canonical Form (sandbox binding); JSON-RPC Error Registry (-31984).
  - AC: `sandbox.required: true` with a context missing `sandbox_id` or
    below `min_isolation` denies with `:sandbox_required` and emits
    `-31984` with `required_isolation`, `received_isolation`, and
    `sandbox_id_present`.
  - Tests: negative (per isolation level), malformed.
- [x] M3.17 Poisoned and quarantined tool-result handling tests.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - Threat Coverage
    And Host-Owned Exclusions (TM.02); `-31988` registry row.
  - AC: poisoned/quarantined results produce quarantine decisions with
    sanitized text only (`sanitized_text` in `data` only when
    `include_sanitized: true`); raw output never crosses.
  - Tests: negative, tamper.
- [x] M3.18 Confirmation-change invalidation matrix.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - Confirmation
    Lifecycle (Digest recomputation).
  - AC: any change since issuance - arguments, sink, actor, `sandbox_id`,
    `isolation_level`, or manifest - fails `:digest_mismatch` or
    `:manifest_digest_mismatch`; tokens are never renewed; a fresh gate
    pass plus re-issue is required.
  - Tests: tamper (one case per changed dimension), negative.
- [x] M3.19 Transport examples: HTTP MCP, stdio MCP, and in-process tools.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - Integration
    Points; CapabilityManifest Canonical Form (`server` field rule).
  - AC: ExDoc examples cover HTTP MCP (canonical server URI) and
    stdio/in-process tools (host-assigned local runner id); both compile
    as doctests or included example modules.
  - Validation: `mix docs` renders both examples; doctests green.
- [x] M3.20 `SigilGuard.AgentCard`: canonical form, digest, sign, verify.
  - Spec: `docs/specs/SP.13-agent-to-agent-trust-statements.md` - Agent
    Card As Capability-Manifest Analog (Card Fields (Normative); Card
    Digest; Card Signing And Verification).
  - AC: `new/1` enforces the closed card schema (`kind` =
    `sigil_guard_agent_card`, `schema_version` `"1"`, sorted lists,
    keyid = SHA-256 derivation of each public key, `expires_at` after
    `issued_at`); violations fail `:invalid_agent_card`.
  - AC: `digest/1` hashes the exact JCS-ordered preimage key set;
    `sign/2,3` wraps the card in DSSE; `verify/2,3` resolves issuers from
    trust material, enforces the JCS byte-equality check, and fails
    untrusted issuers with `:untrusted_issuer` and stale cards with
    `:card_expired`; card golden vectors under
    `test/fixtures/agent_cards/` round-trip byte-identically.
  - Tests: golden vectors, negative, tamper, expiration, malformed.
- [x] M3.21 `SigilGuard.AgentTrust` helpers with delegation-chain
      validation and unknown-peer quarantine.
  - Spec: `docs/specs/SP.13-agent-to-agent-trust-statements.md` -
    Delegation-Chain Validation; Public API Sketch.
  - AC: `attest_agent_request/3` follows the documented order (card
    verify, agent-id binding -> `:unknown_agent`, capability declared ->
    `:unknown_capability`, chain shape/depth/mirror, MIN trust derivation,
    verdict override, from_decision, sign); depth above
    `:max_delegation_depth` (default 8) fails `:delegation_too_deep`;
    chain tamper (reorder, insert, drop, edit, one-sided mirror) fails
    `:delegation_chain_tampered`.
  - AC: without a verified peer card the attestation carries verdict
    `quarantine`, `peer_trust` `"low"`, and no card digest - no code path
    allows an unverified peer; `attest_agent_response/3` and
    `verify_agent_response/3` enforce back-reference, card binding, and
    status/quarantined shape in order.
  - Tests: negative, tamper, replay, expiration, malformed.
- [x] M3.22 JWS-to-DSSE card parity and result-pipeline routing.
  - Spec: `docs/specs/SP.13-agent-to-agent-trust-statements.md` - Card
    Signing And Verification (JWS migration subsection); Acceptance
    Criteria.
  - AC: a shared-keypair parity test validates the documented 1:1 mapping
    from Ed25519-JWS card signing to the DSSE form; verified
    `agent_response` payloads provably route through the result-phase
    scanner/gate pipeline after envelope verification (verification never
    exempts content).
  - Tests: parity (shared keypair), negative.

## M4 - Boundary Scanner And Policy Kernel

> Specs: `SP.04`, `SP.07`, `SP.10`, `SP.11`. Depends on: M1-M3.
> Exit criteria: `./bin/check` clean; M1.02 conformance green;
> streaming properties green (zero leaked prefixes); all 20 sandbox matrix
> cells tested; canonical policy fixtures committed.

- [x] M4.01 `SigilGuard.Boundary` normalized policy decision input.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` - Data
    Model (Policy Decision Input (`SigilGuard.Boundary`)).
  - AC: the struct carries source/sink/phase/origin/actor/identity/
    trust_level/trust_zone/tool/resource plus `source_sensitivity` and the
    sandbox fields; validation rejects out-of-enum values with typed
    errors.
  - Tests: negative, malformed.
- [x] M4.02 Lifecycle phase taxonomy (nine phases).
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Lifecycle Taxonomy.
  - AC: the nine phases (session_start, tool_request,
    permission_requested, permission_resolved, tool_result, file_changed,
    model_ingress, model_egress, session_end) are a closed set shared by
    Boundary, Hooks, and policy `phase:` matchers.
  - Tests: negative (unknown phase), malformed.
- [x] M4.03 `BoundaryPolicy.evaluate/2` with decision combination.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Decision Combination (Normative).
  - AC: deterministic evaluation over Boundary inputs; combination follows
    the normative rules; absent `default` line means `confirm`.
  - Tests: negative, property (determinism: equal inputs, equal outputs).
- [x] M4.04 Policy-file parser: version line, sections, folding.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` - Policy
    File Schema (Grammar).
  - AC: `version 3` mandatory first non-comment line; `[rules]`, `[repo]`
    (v2 grammar verbatim, no folding), and `[contracts]` sections each at
    most once; whitespace-continuation folding in `[rules]`/`[contracts]`;
    files over 256 KiB fail `:policy_too_large`; unknown sections/keys/
    values, duplicate matcher keys, duplicate `default`, or a bad version
    line fail `:invalid_policy_file`; matcher table implemented exactly
    (values OR within a key, keys AND within a rule; rule ids `line_<n>`).
  - Tests: malformed (one fixture per parse-error atom under
    `test/fixtures/boundary_policy/invalid/`), negative.
- [x] M4.05 Policy-file digest and canonical fixtures.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` - Policy
    File Digest; Canonical Example And Fixture Convention.
  - AC: `policy_file_digest` is SHA-256 over the raw bytes exactly as read
    (no normalization); the exact canonical example bytes are committed as
    `test/fixtures/boundary_policy/canonical.policy` with
    `canonical.expected.json` reproducing rules, contracts, repo section,
    and digest byte-deterministically.
  - Tests: golden vectors, negative.
- [x] M4.06 D13 policy filenames and the legacy-filename typed error.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` - Policy
    Filenames (D13, Jointly Owned With SP.11);
    `docs/specs/SP.11-repo-policy-kernel-contracts.md` - V3 Policy
    Filenames (D13).
  - AC: the loader checks `SIGILGUARD_POLICY`, `.sigilguard-policy`,
    `.sigilguard/policy`, `.github/sigilguard-policy` in order; any legacy
    name present under the repo root fails
    `{:error, {:legacy_policy_filename, found, use}}` naming the found
    path and its 1:1 positional replacement, even when a new-name file
    also exists - no silent fallback, no coexistence.
  - AC: candidate paths keep the safe-relative-path rules resolved inside
    the repo root.
  - Tests: negative (each legacy name), malformed.
- [x] M4.07 Precedence and matched-rule explanations.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Precedence.
  - AC: `block > quarantine > confirm > redact > allow` across matching
    rules; `[repo]` keeps its implemented
    `block > require_approval > allow` order and unmatched-path defaults;
    decisions carry matched-rule ids and explanations.
  - Tests: negative, property (precedence total order).
- [x] M4.08 Runtime gate rewire onto `BoundaryPolicy` with the unified
      verdict enum.
  - Spec: `docs/specs/SP.07-runtime-gate-and-streaming-contracts.md` - V3
    Rewire (Gate <-> Kernel Delegation); V3 Decision Contract.
  - AC: the gate evaluates through `BoundaryPolicy`; the unified verdict
    enum (allow/block/confirm/redact/quarantine) replaces the v2 dual
    vocabulary per the spec's mapping table; `%Decision{}` gains typed
    `matched_rules` and `evidence_refs`; source, sink, trust zone, actor,
    resource, and phase appear on runtime decisions.
  - AC: D17 facade contracts stay byte-stable - M1.02 stays green.
  - Tests: negative, property (old-to-new verdict mapping), conformance.
  - Done: SP.07 gained the normative *Gate <-> Kernel Delegation* subsection
    and SP.04 the sandbox opt-in framing (Option 1). The gate builds a
    normalized `Boundary` (phase bridge, evidence digests) and folds
    `BoundaryPolicy.evaluate` into its combination by the unified total order,
    keeping scanner-failure/quarantine/risk-trust; the sandbox matrix is opt-in
    by tool/sandbox presence; `%Decision{}` gained `matched_rules`,
    `evidence_refs`, boundary labels, and `effect` (the post-confirmation
    action, separated from the unified `:confirm`), with the confirmation
    dispatch reading `effect`. M1.02 and every consumer stay green.
- [x] M4.09 Sandbox identity fields on `SigilGuard.Context`.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Sandbox Identity (Isolation Levels).
  - AC: `sandbox_id` and `isolation_level`
    (`:none | :container | :vm | :remote_attested`, nil allowed) plus
    `workspace_root_digest` and network posture fields exist;
    `Context.validate/1` rejects out-of-enum values with
    `:invalid_isolation_level`; omitted level is byte-distinct from
    `"none"` in the context digest.
  - Tests: negative, malformed.
- [x] M4.10 Side-effect mismatch matrix with the fail-closed quarantine
      default.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Fail-Closed Default (Normative); Side-Effect Mismatch Matrix.
  - AC: absent/`:none` isolation on tool phases defaults to `:quarantine`
    (reason `:sandbox_required`, rule id `sandbox.matrix.<class>.<level>`);
    affirmative `:none` on `execute`/`network` blocks outright; multiple
    classes use the strictest cell; no verified manifest means class
    `execute`; only a `[rules]` line with an `isolation:` matcher may
    override a cell - kernel invariants never weaken.
  - Tests: negative, property (strictest-cell selection).
- [x] M4.11 Sandbox matrix cell tests (all 20 cells).
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Side-Effect Mismatch Matrix; Acceptance Criteria.
  - AC: every class x level cell is asserted, including missing-sandbox
    and mismatch cases for risky tools, and the `isolation:absent`
    override path.
  - Tests: negative (20 cells), expiration not applicable, malformed
    (invalid level input).
- [x] M4.12 Sink-aware output contracts (`[contracts]` section).
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Sink-Aware Output Contracts (Contract Vocabulary).
  - AC: `max_size` (floor 64), `no_raw_credentials`, `digest_only_pii`,
    `classes` (`text`/`structured`), and `credential_transform`
    (`mask`/`hash`) parse per the vocabulary; duplicate sinks, unknown
    fields, invalid classes, or `max_size` below 64 fail
    `:invalid_output_contract`; unknown transforms fail
    `:unknown_transform`; a disallowed class escalates to `block` with
    rule `contract.<sink>.class`.
  - Tests: negative, malformed.
- [x] M4.13 Contract transforms and evaluation order.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Transform Semantics (Normative); Evaluation Order (Normative).
  - AC: `truncate` keeps the longest prefix at most `max_size - 11` bytes
    backed off to a codepoint boundary plus the 11-byte `[TRUNCATED]`
    marker (always valid UTF-8, never above `max_size`); `hash` replaces
    spans with the 71-byte `"sha256:" <> hex`; `mask` replaces every
    codepoint with `*`.
  - AC: order is scanner redaction, quarantine effects, then contract
    (class check, credential transform, PII, truncation); no contract runs
    on `block` or `quarantine` verdicts.
  - Tests: property (UTF-8 validity under truncation), negative, malformed.
- [x] M4.14 Lethal-trifecta example policy with doctest.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Dataflow Rules And Lethal Trifecta; Complete Policy File Example.
  - AC: the canonical example's first three rules encode the trifecta
    (`sensitivity:private` x untrusted origin/zone x
    `sink:external,network`): `trust:low,medium` blocks, `trust:high`
    routes to confirm whose token binds the action digest including
    `sandbox_id`; a doctest executes the policy against representative
    inputs.
  - Tests: doctest, negative (all three conjunct drop-outs), property.
- [x] M4.15 Repo policy facts in boundary decisions.
  - Spec: `docs/specs/SP.11-repo-policy-kernel-contracts.md` - Policy Facts
    For Boundary Decisions.
  - AC: the policy-facts map feeds `BoundaryPolicy` exactly per the SP.11
    shape; repo verdict facts appear in decision explanations.
  - Tests: negative, malformed.
- [x] M4.16 `SigilGuard.Hooks` behaviour.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` - Hooks
    Behaviour (Result Semantics).
  - AC: nine optional callbacks map 1:1 to phases as `on_<phase>`;
    `on_session_start/2` and `on_session_end/2` are notification-only, the
    other seven blockable; hooks contribute `{:block, _}`/`{:confirm, _}`
    and advisory signals (risk may raise, never lower; indicators join
    with source `:hook`, rule id `hook.<module>.<phase>`); hooks cannot
    emit allow/redact/quarantine.
  - Tests: negative (per callback), malformed (`:invalid_hook_result`).
- [x] M4.17 Hooks dispatcher: timeout and fail-closed matrix.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Timeouts And Fail-Closed Matrix.
  - AC: every invocation is bounded by `:hook_timeout_ms` (default
    `5_000`); on blockable phases timeout/crash/invalid-result each yield
    verdict `block` with reasons `:hook_timeout`/`:hook_crash`/
    `:invalid_hook_result`; on notification-only phases the same failures
    log-and-continue via telemetry; `{:block, _}` short-circuits remaining
    hooks.
  - Tests: negative (all six matrix cells), tamper (crashing hook).
- [x] M4.18 Adaptive detector behaviour with the deterministic nil path.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Adaptive Detector Behaviour (D5).
  - AC: `SigilGuard.AdaptiveDetector.analyze/3` returns advisory
    indicators (source `:adaptive`) that raise risk but never lower it and
    never produce an allow; detector errors, timeouts, crashes, or
    malformed indicator maps degrade to zero indicators recorded as
    `adaptive_error`; with `:adaptive_detector` unset, decisions are
    byte-identical to a build without the behaviour (proven by test).
  - Tests: negative, malformed, property (nil-path byte equality).
- [x] M4.19 Scanner validators and confidence thresholds.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Scanner Hit Extension And Pattern-Set Split.
  - AC: staged-pipeline validators and confidence scoring are expanded;
    scores land in the additive `confidence` hit field in `0.0..1.0`.
  - Tests: negative, property (score bounds).
- [x] M4.20 Pattern-set split with bundle-suppliable sets and pluggable
      quarantine indicators.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Pattern Sets, Bundle Pattern-Set Entry (Normative).
  - AC: secret, injection, and poisoning sets are distinct; bundle pattern
    entries gain a `set` field and each set can be supplied or overridden
    independently (SP.02 wiring); quarantine consumes the injection and
    poisoning sets with the current seven indicators as built-in defaults.
  - Tests: negative, malformed (bad `set` values), tamper.
  - Done: added the `SigilGuard.PatternSets` resolver (`built_in/0`,
    `resolve/1`) grouping bundle entries by `set`, replacing each set's default
    independently, and compiling to the scanner pattern shape (`secret`) or the
    quarantine indicator shape (`injection`/`poisoning`); tagged built-in
    scanner patterns `set: :secret` and split the seven quarantine indicators
    into `built_in_indicators(:injection)` (6) / `(:poisoning)` (1) with an
    `:indicator_sets` override on `Quarantine.inspect`; wired
    `TrustBundle.pattern_sets/1` to resolve a verified bundle's section
    (fail-closed on a legacy entry without a `set`); pinned the SP.04 Bundle
    Pattern-Set Entry schema (set-derived category, never entry-settable).
    Malformed `set`/`name`/`regex`/`severity` and duplicate names fail
    `:invalid_pattern_set`.
- [x] M4.21 Hit-map additive extension (D17-safe).
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` - Hit
    Map (D17, Additive Only).
  - AC: `scan/1` and `scan_and_redact/1` return shapes are unchanged;
    required keys narrow to `name`/`match`/`offset`/`length`; the built-in
    pipeline always emits `replacement_hint`, `category`
    (`:secret | :injection | :poisoning`), `confidence`, `severity`, and
    `span` (must equal `{offset, length}`); M1.02 conformance stays green.
  - Tests: conformance, negative, property (`span` equality).
- [x] M4.22 `max_match_bytes` and the holdback-window invariant.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Holdback Invariant (Normative).
  - AC: built-in values (aws_access_key 20, private_key 40, 256 for the
    rest) are declared; bundle patterns may declare `1..4096` (default
    256); `Runtime.Stream.new/2` raises the effective window to the
    largest active `max_match_bytes` when the configured window is
    smaller.
  - Tests: negative, property (window >= max pattern bound).
- [x] M4.23 Streaming property tests: every byte-offset split.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Streaming Property-Test Specification (Generators; Latency Budget).
  - AC: for every secret-pattern fixture text: exhaustive two-chunk splits
    at every byte offset, StreamData multi-chunk partitions including
    all-1-byte chunks, mid-codepoint multi-byte UTF-8 splits, and
    grapheme-cluster (combining/ZWJ) splits inside the holdback window.
  - AC: invariants hold: concatenated emissions plus `finish/1` equal the
    single-shot output; no emitted prefix ever contains bytes matching an
    active secret pattern; `finish/1` flushes everything withheld.
  - Tests: property (all generator classes), negative.
- [x] M4.24 Curated split-secret vector file.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Curated Vector File.
  - AC: `test/fixtures/streaming/split_secret_vectors.json` is committed
    with the required vector classes per built-in pattern (first-byte,
    one-before-match-end, mid-match splits; mid-codepoint; grapheme
    cluster; all-1-byte full secret) plus Unicode-confusable negatives
    that MUST NOT match or redact; each vector asserts
    `expected_hit_names` and exact `expected_emitted`.
  - Tests: golden vectors, negative (confusables).
- [x] M4.25 Config-driven trust mapping (core default).
  - Spec: `docs/specs/SP.10-vault-and-identity-contracts.md` -
    Config-Driven Trust Mapping.
  - AC: the small core default ships: an actor-pattern to trust_level map
    with the documented `@spec`; unmatched actors take the documented
    default; the mapping DSL beyond this default stays deferred.
  - Tests: negative, malformed (bad patterns), property (total mapping).

## M5 - Audit, Telemetry, Provenance, And Threat Suite

> Specs: `SP.05`, `SP.09`, `R.06`. Depends on: M1-M4.
> Exit criteria: `./bin/check` clean; M1.02 conformance green;
> all twelve TM families green; proofs verify unmodified 0.2.x checkpoint
> roots.
> Rule for TM tasks (move-don't-duplicate): scenarios already implemented
> in earlier milestones are MOVED into their TM module or referenced by
> exact test name - never copy-pasted; every TM module's `@moduledoc`
> cites its R.06 Control Mapping row numbers and claim level.

- [x] M5.01 Inclusion proofs: generation and verification.
  - Spec: `docs/specs/SP.05-audit-and-release-provenance.md` - Inclusion
    And Consistency Proofs (Tree Construction (Normative Literals);
    Inclusion Proof Verification; Generation API).
  - AC: `SigilGuard.Audit.Proof` generates and verifies inclusion proofs
    over the existing tree with the frozen `sigil-audit-leaf-v1:`/
    `sigil-audit-node-v1:` domain separation; failures produce
    `:invalid_proof`, `:proof_verification_failed`, or `:out_of_range`;
    proofs verify against unmodified 0.2.x checkpoint roots.
  - Tests: golden vectors (`test/fixtures/audit_proofs/` five-event tree),
    negative, tamper.
  - Done: added `SigilGuard.Audit.Proof.inclusion/2` (audit path leaf-to-root,
    `:out_of_range`/`:unsigned_event`) and `verify_inclusion/3` (RFC 9162
    2.1.3.2: `:invalid_proof` for a malformed closed proof object,
    `:out_of_range` for `leaf_index >= tree_size`,
    `:proof_verification_failed` on root mismatch). Exposed the tree
    primitives (`leaf_hash/1`, `node_hash/2`, `leaf_hashes/1`, `levels/1`) on
    `SigilGuard.Audit.Checkpoint` as the single construction source and reused
    them in `merkle_root/1`. Committed the deterministic five-event golden
    vectors (`events`/`tree`/`inclusion_5`/`checkpoint_5`) generated by
    `SigilGuard.AuditProofFixture` with byte-identical regeneration asserted;
    proofs verify against the unmodified checkpoint root. Consistency proofs
    (`consistency/2`, `verify_consistency/3`) land in M5.02.
- [x] M5.02 Consistency proofs and the 1..256 equivalence property.
  - Spec: `docs/specs/SP.05-audit-and-release-provenance.md` - Inclusion
    And Consistency Proofs (Consistency Proof Verification; Golden Vector:
    Five-Event Tree).
  - AC: 3-to-5, 4-to-5, and 5-to-5 consistency vectors verify and
    regenerate byte-identically; a property proves promotion/RFC 9162 root
    equality for sizes 1..256; truncation and fork attempts fail
    `:inconsistent_tree`.
  - Tests: golden vectors, property, tamper, negative.
  - Done: added `SigilGuard.Audit.Proof.consistency/2` (RFC 9162 2.1.4.1
    SUBPROOF over the promotion tree, `:out_of_range`/`:unsigned_event`) and
    `verify_consistency/3` (2.1.4.2: `:invalid_proof` for a malformed closed
    proof object, `:out_of_range` for `first_size` outside `1..second_size`,
    `:inconsistent_tree` on a forked/truncated newer root). Committed the
    `consistency_3_5`/`consistency_4_5` golden vectors (`[H2,H3,N01,H4]` /
    `[H4]`) with byte-identical regeneration asserted. Added a property
    asserting the promotion root equals an independent RFC 9162 recursive root
    for every size 1..256, plus StreamData round-trip properties for random
    consistency `m <= n` and inclusion leaves. Negative/tamper coverage:
    forked roots, tampered/truncated/over-long node lists, unparseable roots.
- [x] M5.03 DSSE checkpoint statements.
  - Spec: `docs/specs/SP.05-audit-and-release-provenance.md` - Witness
    Cosigning (checkpoint statement);
    `docs/specs/SP.09-audit-chain-and-anchor-contracts.md` - Normative
    Constants.
  - AC: `Checkpoint.to_statement/1` builds the
    `https://sigilguard.dev/audit-checkpoint-state/v1` DSSE payload over
    exactly `(merkle_root, tree_size, generated_at)`; existing checkpoint
    records are unchanged.
  - Tests: golden vectors, negative, malformed.
  - Done: added `Checkpoint.to_statement/1` building the in-toto Statement
    whose predicate binds `(merkle_root, tree_size, generated_at)` -
    `tree_size` the event count as a JSON string, `chain_id` included only
    when present, `profile` `sigil_guard_agent_trust/v1` - with a single
    `checkpoint` subject digested by `digest/1` over the unchanged local
    record (signed and unsigned yield the same subject digest). Validates via
    the existing `verify_static_fields/1` (malformed/non-checkpoint maps fail
    `:invalid_checkpoint`). Committed the `expected.json` golden statement
    (byte-identical regeneration asserted); the local record is never
    modified.
- [x] M5.04 Witness cosigning and threshold verification.
  - Spec: `docs/specs/SP.05-audit-and-release-provenance.md` - Witness
    Cosigning.
  - AC: `Audit.Witness.cosign/3` appends `{keyid, sig}` over identical PAE
    bytes without modifying the payload; with `:previous` present the
    consistency proof MUST verify first (failed proof refuses with the
    proof's error); duplicate keyids rejected per SP.01.
  - AC: `verify_threshold/3` counts distinct verified witness keyids from
    the named key set; below m fails `:witness_threshold_not_met`;
    unwitnessed single-signature checkpoints stay valid where no threshold
    policy applies.
  - Tests: negative, tamper, replay (stale previous checkpoint), malformed.
  - Done: added `SigilGuard.Audit.Witness.cosign/3` and `verify_threshold/3`,
    plus the reusable `SigilGuard.Attestation.Envelope.add_signature/3` DSSE
    cosigning primitive (append over identical PAE, payload unchanged,
    duplicate/present keyid fails `:duplicate_keyid`, bad signer
    `:invalid_signer`). `cosign/3`'s `:previous` gate verifies the consistency
    proof from the prior checkpoint to the current envelope's statement first,
    refusing with the proof's error (`:invalid_proof`/`:out_of_range`/
    `:inconsistent_tree`). `verify_threshold/3` counts only witness keyids
    whose signatures verify (tampered/unresolved tolerated), returns the sorted
    verified keyids, fails `:witness_threshold_not_met` below `m`, and surfaces
    structural DSSE errors (`:duplicate_keyid`, `:invalid_payload_type`).
- [x] M5.05 Signed audit event exports and export-package DSSE form.
  - Spec: `docs/specs/SP.05-audit-and-release-provenance.md` - Data Model
    (Signed Audit Event; Event Hash Field List (Exact, Ordered); Export
    Package DSSE Form).
  - AC: signed events match the canonical example and the exact ordered
    event-hash field list; export packages gain optional
    `checkpoint_statement` and proof fields in DSSE form;
    `%SigilGuard.Audit{}` and `sign_event/3` are unchanged (D17).
  - Tests: golden vectors, tamper, negative, plus truncation detection
    (dropped/reordered events in exports are detected).
  - Done: extended `Export.create/2` with `:checkpoint_statement` (the DSSE
    envelope over `Checkpoint.to_statement/1`, signed with `:signer`),
    `:inclusion_proofs` (`:all` or an index list), and `:consistency_proof`
    (`first_size`) - all optional and additive, so a package without them stays
    byte-identical to a 0.2.x export (D17). `Export.verify/3` now matches an
    embedded statement's subject digest to the checkpoint (`:statement_mismatch`)
    and recomputes each embedded inclusion proof against the checkpoint root;
    dropped/reordered events fail `:checkpoint_mismatch` via `Checkpoint.verify`.
    Asserted the frozen event-hash field list (`action, actor, id, result,
    timestamp, type`) and committed the `export.json` golden package
    (byte-identical regeneration + evidence verification).
- [x] M5.06 Privacy classification enforcement.
  - Spec: `docs/specs/SP.05-audit-and-release-provenance.md` - Privacy
    Classification (Normative) (GDPR Stance (Digest-First)).
  - AC: the per-field class table (clear/hashed/redacted/omitted) is
    enforced over every signed event field; hashed fields use the `fh1:`
    form via `hash_field/2`; a missing field-hash key yields
    `"redacted-v1"`; raw secrets never appear in chain events; key
    destruction (crypto-erasure) leaves all verification green.
  - Tests: negative, property (no plaintext survives), tamper.
  - Done: added `SigilGuard.Audit.hash_field/2` (`"fh1:" <> lowercase-hex
    HMAC-SHA256(field_hash_key, value)`, failing closed to `"redacted-v1"`
    for a nil/empty/non-binary key or value) and `classify/2`, which applies
    the class table to the six signed fields - the `hashed` `actor` becomes its
    `hash_field/2` form, the `clear` fields stay verbatim, and unsigned
    host-classified `metadata` is untouched. `classify/2` fails closed to
    `"redacted-v1"` when no field-hash key is given or when it reuses the chain
    key (`:chain_key`), and is idempotent on an already-classified actor.
    Because the hash enters the chain preimage, crypto-erasure of the field-hash
    key leaves chain/proof verification green. A property asserts no raw actor
    survives in the signed canonical bytes; tamper and negative tests included.
- [x] M5.07 OTel attribute rename to `sigilguard.*` with cardinality
      opt-in.
  - Spec: `docs/specs/SP.05-audit-and-release-provenance.md` - Telemetry
    And OTel (D16 Resolution: Attribute Namespace; Attribute Cardinality
    And Sampling).
  - AC: every emitted attribute uses `sigilguard.*` (or the unchanged
    `url.full`); the rename table is test-covered, including the hashed
    exceptions (`sigilguard.actor.hash`, `sigilguard.identity.hash`,
    `sigilguard.confirmation.actor.hash`, `sigilguard.payload.digest`);
    removed `sigil.registry.*`/`sigil.envelope.*` attributes are never
    emitted; high-cardinality attributes require
    `include_high_cardinality: true`.
  - Tests: negative, golden mapping table, redaction (decision attributes
    never carry raw text).
  - Done: rewrote the `Telemetry` `@attribute_map` to the `sigilguard.*`
    namespace (mechanical `sigil.`->`sigilguard.` + drop `.security.`, the
    hashed exceptions, and the `<subject>.digest` family), plus the
    `sigilguard.event`/`component`/`operation`/`measurement.*` prefixes;
    removed the `sigil.registry.*` (`count`/`endpoint`/`source`) and
    `sigil.envelope.*` (`status`/`reason`) entries so they are never emitted.
    `otel_attributes/4` and `attach_otel_forwarder/3` gained
    `include_high_cardinality` (default `false`), dropping the digest/hash/id/
    uri attributes unless opted in. A test asserts no attribute keeps the
    retired `sigil.` prefix; the hashed exceptions, high-card opt-in, url.full,
    and registry/envelope removal are covered. Pinned the digest-family form
    and the complete high-card set in SP.05 D16.
- [x] M5.08 CloudEvents projection.
  - Spec: `docs/specs/SP.05-audit-and-release-provenance.md` - CloudEvents
    Projection.
  - AC: projection emits `specversion` `1.0`, type
    `io.sigilguard.decision.v1`, and privacy-filtered `data` only.
  - Tests: golden shape, negative (privacy filter).
  - Done: added `SigilGuard.Audit.CloudEvents.project/2`, mapping a signed
    event to a CloudEvents 1.0 envelope (`specversion` `1.0`, `type`
    `io.sigilguard.decision.v1`, host-configured `:source` defaulting to
    `urn:sigilguard`, `time`/`id` from the event, `datacontenttype`
    `application/json`). Trace context projects to the `traceparent` extension
    only when both `trace_id` and `span_id` are present. `data` is the
    privacy-filtered event: scalar fields verbatim (the `actor` is whatever the
    event carries, so `classify/2` runs first) plus a metadata allowlist of the
    reserved SP.05 keys - raw content and unclassified host keys are omitted,
    and `trace_id`/`span_id` never appear in `data`. A golden-shape test pins
    the envelope; negative tests assert no raw prompt/actor/host key leaks.
- [x] M5.09 Audit read and query API (pure reads).
  - Spec: `docs/specs/SP.05-audit-and-release-provenance.md` - Audit Read
    And Query API.
  - AC: `Audit.tip/1`, `Audit.query/2`, and `checkpoint_boundaries/2` are
    additive on `SigilGuard.Audit`, never write to any table/store/event,
    and emit no telemetry; `tip/1` fails `:empty_chain`/`:unsigned_event`;
    `query/2` implements the closed option set (`:from_index`,
    `:to_index`, `:id`, `:type`, `:from_time`, `:to_time`; AND-composed,
    chain order, `{:ok, []}` for empty) with `:out_of_range`/
    `:invalid_query` errors; `checkpoint_boundaries/2` fails span
    mismatches with `:checkpoint_mismatch`.
  - Tests: negative, malformed, property (purity: state unchanged).
  - Done: added the three additive pure reads to `SigilGuard.Audit`. `tip/1`
    returns the last event's `{index, event_id, hmac, timestamp}` without
    verifying the chain (`:empty_chain`/`:unsigned_event`). `query/2` validates
    a closed option set (unknown key or malformed value/time -> `:invalid_query`;
    index outside `0..length-1` or `to < from` -> `:out_of_range`), AND-composes
    the filters, preserves chain order, and returns `{:ok, []}` for no match.
    `checkpoint_boundaries/2` locates each checkpoint's `first`/`last_event_id`
    span and checks its length against `event_count` (`:checkpoint_mismatch`),
    yielding `nil` indices for empty checkpoints and `:invalid_query` for a
    non-checkpoint term. A purity test asserts the reads emit no telemetry.
- [x] M5.10 Bind attestations to audit evidence refs.
  - Spec: `docs/specs/SP.05-audit-and-release-provenance.md` - Data Model;
    `docs/specs/SP.01-sigilguard-trust-profile.md` - Data Model (evidence).
  - AC: attestation predicates carry evidence refs
    (`kind: checkpoint/export/anchor`) resolving to audit artifacts;
    round-trip from decision to attestation to audit event is asserted.
  - Tests: negative, tamper (dangling refs detected).
  - Done: added `SigilGuard.Audit.Evidence` with `ref/2` (build the SP.01
    `%{"kind", "ref"}` from a checkpoint/export/anchor `digest/1`), `validate/1`
    (closed kind + non-empty binary ref, else `:invalid_evidence`), and
    `resolve/2` (every ref's `(kind, digest)` must match a supplied artifact,
    else `:dangling_evidence_ref`). `Attestation.from_decision/3` now validates
    the `:evidence` option before building the predicate (`:invalid_evidence`),
    so decision, attestation predicate, and audit-event `metadata["evidence"]`
    carry the identical resolvable ref. Round-trip, negative, and tamper
    (dangling/mislabelled ref) tests included.
- [x] M5.11 `SigilGuard.HTTPClient` behaviour and anchor-store conversion.
  - Spec: `docs/specs/SP.05-audit-and-release-provenance.md` -
    SigilGuard.HTTPClient Behaviour (D9).
  - AC: the behaviour (`request/5`) exists with the documented contract:
    resolution per-call `opts[:http_client]` then app env then fail;
    missing client fails `{:error, :http_client_not_configured}` at first
    use, never a silent no-op; timeout default `5_000` ms passed in opts;
    no store-level retries; adapter errors surface as
    `{:error, {:http_client_error, reason}}`, crashes as
    `{:error, {:http_client_error, :adapter_crash}}`; bodies over
    `:max_body_bytes` (default `1_048_576`) fail `:response_too_large`.
  - AC: `Audit.Anchor.Store.HTTP` has zero direct `Finch.` calls (the dep
    itself leaves in M6.11); `Store.LocalFile` is unchanged.
  - Tests: negative, malformed, tamper (oversized/mangled responses),
    expiration (timeout).
  - Done: added the `SigilGuard.HTTPClient` behaviour (`request/5`). Converted
    `Audit.Anchor.Store.HTTP` to resolve the host client (per-call
    `:http_client`, then app env, else `:http_client_not_configured` -
    including a module not exporting `request/5`), pass the resolved `:timeout`
    (default `5_000`, `:infinity` allowed) in opts with no store retries, and
    surface adapter `{:error, reason}` as `{:http_client_error, reason}`,
    raises/exits as `{:http_client_error, :adapter_crash}`, non-2xx as the
    existing `{:http_error, status}`, and bodies over `:max_body_bytes`
    (default `1_048_576`) as `:response_too_large`. Zero direct `Finch.` calls
    remain; `Store.LocalFile` is untouched. The existing Bypass suite runs
    through a test-support Finch adapter injected via app env, plus new contract
    tests (resolution, error/crash/no-status surfacing, oversized/mangled body,
    timeout pass-through) with stub adapters.
- [x] M5.12 WORM anchor adapter and release SBOM verification docs.
  - Spec: `docs/specs/SP.05-audit-and-release-provenance.md` - Release
    Provenance (D15); Security Considerations.
  - AC: host-owned WORM/append-only anchor adapter guidance and SBOM
    verification steps are ExDoc-rendered; SBOM digest drift at
    verification fails with `:sbom_digest_mismatch`.
  - Validation: `mix docs` renders; commands in the docs execute as
    written.
  - Done: added `Mix.Tasks.SigilGuard.Sbom.verify_file/2` and a `--sha256`
    switch that hash the SBOM's raw bytes and fail `:sbom_digest_mismatch` on
    drift (case-insensitive on the expected digest) before the structural
    checks. Added the ExDoc-rendered `guides/release-and-anchoring.md`
    (wired into `mix.exs` extras under a Guides group) covering SBOM generation
    and two-level verification, `gh attestation verify`, the `SigilGuard.HTTPClient`
    seam, and a `require_worm`/signed-receipt WORM anchor-store recipe - every
    command verified to execute as written.
- [x] M5.13 Release provenance workflow readiness (SLSA L3).
  - Spec: `docs/specs/SP.05-audit-and-release-provenance.md` - Release
    Provenance (D15).
  - AC: the maintainer-triggered tagged-release workflow is configured to run
    `actions/attest` in an isolated OIDC/write job with subjects = Hex tarball
    + SBOM; SLSA and custom `gh attestation verify` checks gate publish; the
    release additionally signs an SP.01 `release` predicate against both
    subjects whose directly inspectable `release` object names the validated
    package/version and both artifact `{name, sha256}` entries; a CI example
    shows consumer-side verification.
  - Tests: release-statement builder and negative verification paths are
    unit-tested; tag execution remains maintainer-owned.
  - Done: added `mix sigil_guard.release_statement` (computes each artifact's
    SHA-256 and emits the profile-valid `.../release/v1` statement whose action
    digest and `predicate.release` object bind the validated package/version and
    sorted `{name, sha256}` artifacts; 100% covered). Rewired
    `.github/workflows/publish.yml` to `--sha256`-verify the SBOM, attest both
    subjects with SLSA and the custom release predicate via `actions/attest`,
    and gate the environment-scoped Hex job on both `gh attestation verify`
    forms. The publish job compares a fresh build before publish and the
    registry download afterward with the attested tar. Added a consumer-side
    verification CI example to the release guide. Workflow-level tag execution
    and environment protection are maintainer-owned; the Elixir builders are
    unit-tested.
- [x] M5.14 Rename the legacy scanner interception audit event.
  - Spec: `docs/specs/SP.09-audit-chain-and-anchor-contracts.md` - V3
    Extensions (Owned By SP.05).
  - AC: the old interception event name is replaced by a neutral security
    event; chain verification over historical events with the old name
    still verifies (names are data, not structure).
  - Done: renamed `SigilGuard.Audit.EventType`'s `:sigil_interception` /
    `"SigilInterception"` to the neutral `:scanner_interception` /
    `"ScannerInterception"`, retiring the `sigil` idiom from the emitted
    vocabulary. Added a `verify_chain` test proving a chain signed under the old
    `"SigilInterception"` type string still verifies (the HMAC covers the type
    value, not a known-name enum) and pinned the rename + name-agnostic
    verification in SP.09.
  - Tests: negative, golden vectors (historical chain).
- [x] M5.15 TM.01 threat family - prompt injection via tool results.
  - Spec: `docs/research/R.06-agentic-threat-model-and-control-mapping.md`
    - Control Mapping row 1; Test Families; `SP.04`.
  - AC: `test/sigil_guard/threat_model/tm01_injection_via_tool_results_test.exs`
    proves result-phase scanning, streaming holdback, and sink contracts
    handle the attack fixtures at the documented claim level (mitigates).
  - Tests: negative, tamper, malformed.
  - Done: added the TM.01 module whose `@moduledoc` cites R.06 row 1 (ASI01,
    claim mitigates) and the sourced PR-title-hijack/exfiltration attack, and
    references the base-control tests by exact name (no duplication). It drives
    the controls end-to-end with the fixtures: the gate blocks an injected tool
    result, quarantine flags `ignore_instructions`/`exfiltration_request`, the
    sink-aware contract redacts a secret bound for an external sink, streaming
    holdback prevents a chunk-straddling secret from being emitted, and a
    display:none-hidden instruction is still quarantined; negatives (benign
    result allowed, no leak) and malformed inputs are covered.
- [x] M5.16 TM.02 threat family - tool poisoning via descriptions/metadata.
  - Spec: `R.06` - Control Mapping row 2; `SP.03` (manifest digest
    pinning).
  - AC: `.../tm02_tool_poisoning_test.exs` proves description/annotation/
    schema drift denies via manifest digest pinning (mitigates).
  - Tests: negative, tamper.
  - Done: added the TM.02 module (R.06 row 2, ASI02/ASI04, mitigates) citing
    the MCPTox poisoning attack and referencing the base tests by name. Drives
    `ToolGateway.verify_manifest/2` with poisoned-drift fixtures: an unchanged
    manifest verifies, while a poisoned description or annotations drift to
    `:manifest_digest_mismatch` and a poisoned input schema is rejected;
    tamper (text swapped under a pinned digest) and malformed/unknown manifests
    fail closed.
- [x] M5.17 TM.03 threat family - line jumping.
  - Spec: `R.06` - Control Mapping row 3; `SP.03` (verify-before-list).
  - AC: `.../tm03_line_jumping_test.exs` proves `tools/list` content is
    verified before any definition reaches model context and before any
    invocation (mitigates).
  - Tests: negative, tamper.
  - Done: added the TM.03 module (R.06 row 3, ASI01/ASI02, mitigates) citing
    the line-jumping attack (instructions smuggled into a tool definition that
    reach the model during `tools/list`, before any invocation) and referencing
    the base tests by name. Drives `verify_manifest/2` and
    `verify_list_changed/2`: a clean entry verifies, a poisoned line-jump
    description is rejected with `:manifest_digest_mismatch` before exposure, a
    tool absent from the pinned set fails `:unknown_manifest`, and a refreshed
    list with a poisoned entry (and malformed input) fails closed.
- [x] M5.18 TM.04 threat family - schema injection.
  - Spec: `R.06` - Control Mapping row 4; `SP.03` (Suspicious Required
    Parameters).
  - AC: `.../tm04_schema_injection_test.exs` proves adversarial required
    params (for example credential-shaped names) are disclosed, digest
    bound, recomputed, and force confirm (mitigates + detects).
  - Tests: negative, tamper, malformed.
  - Done: added the TM.04 module (R.06 row 4, ASI02/ASI03, claim
    **mitigates + detects**) citing the schema-injection credential-theft
    attack and referencing the base tests by exact name. Drives both facets
    of the `suspicious_params` disclosure/digest control: `guard_request/3`
    forces `{:confirm, "suspicious_required_param"}` (with `deny_reason`,
    `suspicious_params`, a 64-hex `action_digest`, and `manifest_digest`) for
    an honestly disclosed credential-shaped required param - including one
    buried in a nested `allOf` - while a benign manifest does not (mitigates);
    an undisclosed suspicious param fails `:suspicious_required_param` and an
    injected required param drifting a pinned schema fails
    `:schema_digest_mismatch` via `verify_manifest/2` (detects). Negative
    (benign allowed), tamper (undisclosed/drifted schemas), and malformed
    (bad `suspicious_params` list, empty/unknown manifest) fail closed.
- [x] M5.19 TM.05 threat family - rug pull / TOFU drift.
  - Spec: `R.06` - Control Mapping rows 5 and 18; `SP.03` (list_changed).
  - AC: `.../tm05_rug_pull_test.exs` proves drift rejection and that
    `notifications/tools/list_changed` drops cached approvals and forces re-verification,
    covering the config-swap analog (mitigates).
  - Tests: negative, tamper, replay.
  - Done: added the TM.05 module (R.06 rows 5 and 18, ASI04/ASI05, claim
    **mitigates**; row 18 out-of-scope for the IDE, mitigates the analogous
    config-swap pattern) citing the rug-pull / Cursor "MCPoison"
    (CVE-2025-54136) attack and referencing the base tests by exact name.
    Drives re-verification and token binding with rug-pull fixtures: a swapped
    description or input schema on a `notifications/tools/list_changed` refresh is rejected by
    `verify_list_changed/2` (`:manifest_digest_mismatch` / `:schema_digest_mismatch`)
    while an unchanged tool re-lists cleanly; a confirmation token bound to the
    benign manifest digest stops applying once the tool rug-pulls or its config
    is swapped (version bump) - `Confirmation.verify/5` fails
    `:manifest_digest_mismatch`, so any change forces fresh confirmation
    (the config-swap analog for row 18). Replay (single-use consume then
    `:replay_detected`), expiration (`:expired` past TTL), and malformed
    (non-list refresh -> `:invalid_manifest`) fail closed. Uses real
    `CapabilityManifest.digest/1` values so the drift is a genuine digest change.
- [x] M5.20 TM.06 threat family - confused deputy and consent replay.
  - Spec: `R.06` - Control Mapping rows 6 and 21; `SP.01`, `SP.03`.
  - AC: `.../tm06_confused_deputy_test.exs` proves audience/resource/actor
    binding plus nonce replay scope and token single-use defeat replayed
    or forged approvals (mitigates, partial).
  - Tests: negative, replay, expiration, tamper.
  - Done: added the TM.06 module (R.06 rows 6 and 21, ASI03/ASI09, claim
    **mitigates (partial)** for row 6 / **mitigates (the token)** for row 21;
    host-owned OAuth consent and human judgment named out of scope) citing the
    confused-deputy consent-cookie-replay and spoofed-approval attacks and
    referencing the base tests by exact name. Drives three control surfaces
    with confused-deputy fixtures: `guard_request/3` refuses a credential minted
    for the wrong audience (`:audience_mismatch`, `accepted_audiences ==
    ["repo-mcp"]`) or resource (`:resource_mismatch`) while matching
    audience/resource is allowed; a signed consent attestation binds actor +
    nonce with a `{actor, nonce}` single-use replay scope (second verify ->
    `:replay_detected`) and DSSE expiry (`:expired_attestation`); and a
    confirmation token bound to action/payload/context (incl. actor and
    `sandbox_id`)/manifest rejects a rebound actor (`:digest_mismatch`), a forged
    HMAC body (`:invalid_signature`), a single-use replay (`:replay_detected`),
    and an expired approval (`:expired`); a malformed token fails closed
    (`:invalid_token`). Uses an Ed25519 `TrustedSigner` for the DSSE attestation.
- [x] M5.21 TM.07 threat family - token passthrough and session hijacking.
  - Spec: `R.06` - Control Mapping rows 7 and 8; `SP.03`, `SP.05`.
  - AC: `.../tm07_passthrough_session_test.exs` proves the explicit
    passthrough deny (`:token_passthrough_denied`) and the session-hijack
    assists (per-action nonce, `list_changed` re-verification, audit
    session boundary) at their claim levels (mitigates; detects partial).
  - Tests: negative, replay, tamper.
  - Done: added the TM.07 module (R.06 rows 7 and 8, ASI03/ASI02, claim
    **mitigates** for row 7 / **detects (partial)** for row 8; transport and
    session lifecycle named host-owned) citing the token-passthrough and
    resumable-stream / `list_changed` session-hijack attacks and referencing the
    base tests by exact name. Row 7: `guard_request/3` denies a client token
    reflected at the gateway's own resource (`:token_passthrough_denied`, with
    `audience`/`self_resource` metadata) while a credential for a legitimate
    upstream audience is allowed. Row 8 assists: `verify_list_changed/2` rejects
    a drifted (`:manifest_digest_mismatch`) or wholly new
    (`:unknown_manifest`) tool smuggled into a refresh while a clean refresh
    re-verifies; a per-action approval nonce is single-use per actor
    (`:replay_detected`); and an actor-scoped HMAC audit chain records
    mid-session actions so tampering is detected (`{:broken, 1}` via
    `verify_chain/3`). Malformed refresh input fails closed
    (`:invalid_manifest`). Note: SigilGuard has no `session_id`; the
    "audit session boundary" is realized as the actor-scoped audit chain, and
    the transport session stays host-owned (documented in the module).
- [x] M5.22 TM.08 threat family - memory and context poisoning.
  - Spec: `R.06` - Control Mapping row 9; `SP.04` (model-ingress gating).
  - AC: `.../tm08_memory_poisoning_test.exs` proves retrieved memory/
    context crosses the scanner and trust-zone policy at model ingress
    with digest provenance (mitigates + detects).
  - Tests: negative, tamper, malformed.
  - Done: added the TM.08 module (R.06 row 9, ASI06, claim
    **mitigates + detects**) citing the MemoryGraft attack (arXiv 2512.16962;
    memory-store/RAG index named host-owned) and referencing the base tests by
    exact name. Drives `Gate.evaluate/2` at model ingress (Context phase
    `:inbound_user` -> lifecycle `:model_ingress`, `origin: :resource`) with
    retrieved-memory fixtures: a grafted record carrying injected instructions
    is quarantined/blocked (action in `[:block, :quarantine, :confirm]`, not
    allowed) with the `:ignore_instructions` quarantine indicator and an
    explaining policy rule firing (mitigates + detects), and a SHA-256
    `content_hash` payload digest is bound to the decision (and mirrored in
    `audit_metadata`) as provenance on every ingested record - poisoned or clean.
    Clean memory is allowed yet still carries the provenance digest (negative);
    a display:none-hidden injection is still caught (`:hidden_html_instruction`,
    tamper); non-binary payloads fail closed to a `%Decision{}` without raising
    (malformed). Distinct from TM.01 (tool-result injection): ingress phase,
    retrieved-memory origin, and the digest-provenance assertion no prior test
    makes.
- [x] M5.23 TM.09 threat family - lethal-trifecta dataflow.
  - Spec: `R.06` - Control Mapping rows 10 and 11; `SP.04` (Dataflow Rules
    And Lethal Trifecta).
  - AC: `.../tm09_lethal_trifecta_test.exs` proves the conjunction rule
    blocks/confirms per trust level and that untrusted-origin content
    never enters exec/command sinks (mitigates; execution runtime
    out-of-scope).
  - Tests: negative, property (conjunct coverage), tamper.
  - Done: added the TM.09 module (R.06 rows 10 and 11, ASI01/ASI02/ASI05,
    claim **mitigates** for row 10 / **mitigates (dataflow); out-of-scope (the
    runtime that executes)** for row 11) citing Willison's lethal trifecta and
    referencing the base tests by exact name. Loads the shipped
    `canonical.policy` fixture and drives `BoundaryPolicy.evaluate/2`: the
    trifecta conjunction (private data x untrusted origin+zone x external sink)
    blocks low/medium trust and routes high trust to a confirmation (row 10); a
    StreamData property proves exact-conjunct coverage - dropping any single leg
    (private-data, untrusted-exposure, or external-sink) falls through to
    `:allow` at every trust level. Row 11: untrusted content at `:tool_request`
    is blocked by the non-overridable invariant (reason "untrusted zone may not
    request tools") and an `execute` side-effect with `:none` isolation blocks
    via the sandbox matrix (rule `sandbox.matrix.execute.none`) - the runtime
    that would execute is out of scope. Tamper: a scrubbed benign-looking
    payload still blocks (the verdict is label-driven, not a content classifier);
    malformed: a boundary missing required digests fails closed to `:block`.
- [x] M5.24 TM.10 threat family - A2A impersonation and delegation abuse.
  - Spec: `R.06` - Control Mapping rows 12, 13, and 20; `SP.13`.
  - AC: `.../tm10_a2a_abuse_test.exs` proves card verification against
    bundle issuers, unknown-agent quarantine, and the delegation-chain
    tamper/depth rules (mitigates; detects-at-boundary for rogue agents).
  - Tests: negative, tamper, replay, expiration.
  - Done: added the TM.10 module (R.06 rows 12, 13, 20, ASI03/ASI07/ASI10,
    claim **mitigates** for rows 12/13 / **detects-at-boundary** for row 20)
    citing the A2A impersonation / delegation-scope-abuse / rogue-agent attacks
    and referencing the base tests by exact name. Drives `AgentCard.verify/3`
    and `AgentTrust` with A2A-abuse fixtures: a bundle-issued card verifies while
    an unrecognized issuer fails `:unknown_key_id`, a bundle key lacking the
    `agent_card` role fails `:untrusted_issuer`, an expired card fails
    `:card_expired`, and a payload swapped under a valid signature fails
    `:invalid_signature` (row 12). A peer with no verified card attests a
    `quarantine` verdict with the `agent.unknown_peer.quarantine` rule, and
    `require_peer_card` denies with `:unknown_agent` (row 20). Delegation chains
    accept depth 8 but reject depth 9 with `:delegation_too_deep`, and a
    reordered chain fails `:delegation_chain_tampered` against its signed mirror
    (row 13). A single-use agent-response nonce cannot be replayed
    (`:replay_detected`), and a non-envelope card fails closed
    (`:invalid_envelope`). Uses Issuer/Agent/Local/Impostor Ed25519 signers.
- [x] M5.25 TM.11 threat family - supply chain.
  - Spec: `R.06` - Control Mapping rows 14-17; `SP.02` (verification,
    quarantine).
  - AC: `.../tm11_supply_chain_test.exs` proves tampered/revoked/replayed
    bundle and manifest drift detection with quarantine evidence, and
    documents the out-of-scope tooling-RCE rows as assume-compromised
    posture (detects, partial; out-of-scope rows cited).
  - Tests: negative, tamper, replay.
  - Done: added the TM.11 module (R.06 rows 14-17, ASI04/ASI05, claim
    **detects (partial)** row 14 / **out-of-scope (infra); detects drift** row
    15 / **out-of-scope** rows 16-17) citing the postmark-mcp BCC backdoor
    (v1.0.16), the Smithery `dockerBuildPath` path traversal, and CVE-2025-49596
    / CVE-2025-6514, and referencing the base tests by exact name. Mirrors the
    SP.02 `bundle_document/0` + signer setup and drives `TrustBundle.verify/2`
    and `load/2`: a genuine bundle verifies, a tampered payload fails
    `:invalid_signature` and records a quarantine entry
    (`Quarantine.list/1`, with the decoded `bundle_id`), a revoked-key signature
    fails `:revoked_key`, and a rolled-back bundle replayed after a newer one
    fails `:sequence_below_floor`; a backdoored capability manifest drifts to
    `:manifest_digest_mismatch` via `CapabilityManifest.verify/2`; a non-envelope
    fails closed `:invalid_envelope`. Rows 16-17 are asserted evidence-only - an
    actor-scoped HMAC audit chain records tamper-evident boundary decisions
    around the affected tool (`{:broken, 1}`), with no prevention claim per the
    out-of-scope definition.
- [x] M5.26 TM.12 threat family - repudiation, audit tamper, truncation.
  - Spec: `R.06` - Control Mapping rows 19 and 22; `SP.05`.
  - AC: `.../tm12_repudiation_test.exs` proves chain tamper and truncation
    are detectable via HMAC chain, checkpoints, inclusion/consistency
    proofs, and anchors, and that per-hop attestation evidence
    reconstructs propagation paths (mitigates + detects; evidence-only for
    cascades).
  - Tests: tamper, negative, property (truncation detection).
  - Done: added the TM.12 module (R.06 rows 19 and 22, ASI08/ASI03, claim
    **partial (evidence-only)** for row 19 / **mitigates + detects** for row
    22) and referenced the base audit/proof/export/evidence tests by exact
    name. Drives `Audit.verify_chain/3`, `Checkpoint.create/2` and
    `verify/3`, `Proof.inclusion/2`, `Proof.consistency/2`,
    `Proof.verify_inclusion/3`, `Proof.verify_consistency/3`, `Anchor.verify/2`,
    `Export.create/2` and `verify/3`, `Evidence.resolve/2`, and
    `Attestation.from_decision/3`: a signed anchored export binds a specific
    event with an inclusion proof and anchor; body tamper breaks the HMAC chain;
    HMAC tamper breaks checkpoint verification; proof and anchor tamper fail
    closed; a StreamData property proves every proper prefix verifies as an
    append-only prefix of the full checkpoint but cannot satisfy the full
    checkpoint root as the newer root (truncation/fork signal); a forged
    continuation segment fails against a stored tip; and per-hop agent request /
    response attestations plus checkpoint/export/anchor evidence refs
    reconstruct the cascade path without claiming automatic containment.

## M6 - Legacy Removal, Dependency Cut, And Migration Gate

> Specs: `SP.12`, `SP.06`, `SP.01` (V3 Configuration Surface).
> Depends on: M1-M5.
> Exit criteria (tier-2 consolidated gate): `./bin/check` clean;
> M1.02 conformance green; the M6.24 completeness script proves every
> deleted surface has a 1:1 `MIGRATING-1.0.md` row; runtime dependency set
> is exactly the intended minimal set (`:telemetry`, `:nimble_options`,
> `:jason`); the reference-consumer upgrade branch (M6.29)
> builds and passes its full suite plus its security-conformance
> acceptance tests, with all findings folded back (M6.30).

- [x] M6.01 Delete `SigilGuard.Registry`.
  - Spec: `docs/specs/SP.12-legacy-remote-bundle-adapter-contracts.md` -
    V3 Removal Map.
  - AC: the module is deleted (not hidden); `fetch_bundle/1`,
    `resolve_did/2`, `resolve_key/2`, `fetch_policies/1` map to their
    MIGRATING rows; old registry tests move to migration/removal tests.
  - Tests: removal test (module absent; calls raise cleanly), conformance.
  - Done: deleted `lib/sigil_guard/registry.ex`, replaced
    `test/sigil_guard/registry_test.exs` with `registry_removal_test.exs`, and
    removed the deleted adapter from public module docs / ExDoc grouping.
    Removal assertions prove `SigilGuard.Registry` is not loadable and
    `fetch_bundle`, `resolve_did`, `resolve_key`, and `fetch_policies` raise
    `UndefinedFunctionError` through `apply/3`.
- [x] M6.02 Delete `SigilGuard.Registry.Bundle`.
  - Spec: `SP.12` - V3 Removal Map.
  - AC: deleted; provenance checks live in `TrustBundle` verification;
    legacy golden vectors preserved under `test/fixtures/historical/`.
  - Tests: removal test, golden vectors (historical still parse as
    fixtures).
  - Done: deleted `lib/sigil_guard/registry/bundle.ex`, removed the old
    provenance test module, extended `registry_removal_test.exs` to prove
    `SigilGuard.Registry.Bundle` is not loadable and its legacy
    `canonical_bytes`, `digest`, `sign`, and `verify` calls raise
    `UndefinedFunctionError`, and preserved the old bundle shape in
    `test/fixtures/historical/legacy_registry_bundle.json` with a parser-only
    fixture assertion.
- [x] M6.03 Delete `SigilGuard.Registry.Cache`.
  - Spec: `SP.12` - V3 Removal Map.
  - AC: deleted; `TrustBundle.Cache` is the only cache; no ETS table or
    supervision child remains for the registry path.
  - Tests: removal test, negative (boot has no registry children).
  - Done: deleted `lib/sigil_guard/registry/cache.ex`, removed the old cache
    test module, removed the `registry_enabled?` supervisor branch and
    `SigilGuard.Finch`/`SigilGuard.Registry.Cache` child specs from application
    boot, removed the cache module from public docs / ExDoc grouping, and
    extended `registry_removal_test.exs` to prove the module is not loadable,
    cache calls raise `UndefinedFunctionError`, and the running supervisor has
    no registry cache or Finch children.
- [x] M6.04 Delete `SigilGuard.Profile`.
  - Spec: `docs/specs/SP.01-sigilguard-trust-profile.md` - Public Modules
    Removed In V3.
  - AC: deleted; `SigilGuard.TrustProfile` is the replacement; all doc
    references updated.
  - Tests: removal test, conformance.
  - Done: deleted `lib/sigil_guard/profile.ex`, removed the old profile test
    module, removed `SigilGuard.Profile` from ExDoc grouping, and extended
    `registry_removal_test.exs` to prove the module is not loadable and legacy
    profile helper calls raise `UndefinedFunctionError`.
- [x] M6.05 Delete `SigilGuard.Envelope`.
  - Spec: `docs/specs/SP.06-envelope-and-native-backend-contracts.md` - V3
    Transition Rules; `SP.01` - Migration: Envelope To Attestation.
  - AC: deleted; the Envelope-to-Attestation field mapping table is
    reproduced 1:1 in `MIGRATING-1.0.md` (M6.18); the known-consumers note
    (two call sites: tool-args metadata attach and socket auth) has exact
    v3 replacement calls documented.
  - Tests: removal test, conformance.
  - Done: deleted `lib/sigil_guard/envelope.ex`, removed the direct envelope
    test module, removed legacy envelope callbacks from `SigilGuard.Backend`
    and `SigilGuard.Backend.Elixir`, removed the module from public docs /
    ExDoc grouping, and extended `registry_removal_test.exs` to prove
    `SigilGuard.Envelope` is not loadable and legacy `canonical_bytes`, `sign`,
    `verify`, `generate_timestamp`, and `generate_nonce` calls raise
    `UndefinedFunctionError`. Existing gateway signed-request helpers now fail
    closed with `:legacy_envelope_removed` for envelope-bearing requests until
    M6.25 removes legacy `_sigil*` reading entirely.
- [x] M6.06 Move legacy envelope/profile vectors to
      `test/fixtures/historical/`.
  - Spec: `SP.06` - Known Consumers; V3 Transition Rules (fixture path).
  - AC: old golden vectors live under `test/fixtures/historical/` and are
    exercised only by migration/removal tests; the old-vocabulary scan
    exempts that path.
  - Tests: golden vectors (historical), negative (nothing under `lib/`
    reads them).
  - Done: moved
    `test/fixtures/envelope_golden_vectors.sigil_protocol_0_1_5.json` to
    `test/fixtures/historical/envelope_golden_vectors.sigil_protocol_0_1_5.json`,
    updated the SP.06 fixture-path reference, and extended
    `registry_removal_test.exs` with parse-only historical vector assertions
    plus a negative scan proving no `lib/` file reads `test/fixtures/historical`.
- [x] M6.07 Remove public examples centered on verdict-only envelopes.
  - Spec: `SP.01` - Public API Surface; `SP.06` - V3 Transition Rules.
  - AC: no README/ExDoc example signs or verifies a verdict-only envelope;
    replacements use `SigilGuard.Attestation` statements.
  - Validation: docs vocabulary scan clean; `mix docs` renders.
  - Done: removed the public verdict-only envelope module from ExDoc in M6.05
    and rewrote the remaining `SigilGuard.MCP.Gateway` /
    `SigilGuard.ToolGateway.Base` signed-envelope public docs so they describe
    v3 fail-closed behavior and point to Agent Trust attestations instead of
    showing sign/verify examples. A README/lib/docs scan confirms no public
    example calls `SigilGuard.Envelope`, `sign_envelope`, or `verify_envelope`.
- [x] M6.08 `SigilGuard.Config` strict closed-key validation.
  - Spec: `SP.01` - V3 Configuration Surface.
  - AC: `SigilGuard.Config.validate!/1` runs at `SigilGuard.Runtime` startup
    (or `validate!/0` for the application-environment fallback) and fails
    closed with `SigilGuard.ConfigError`: reason
    `:legacy_contract_removed` for removed keys, `:unknown_config_key`
    for unrecognized keys; every message names the offending key and
    `MIGRATING-1.0.md`; kept keys (`:trust_bundle`, `:scanner_patterns`,
    `:http_client`, `:attestation_ttl_ms`, `:max_skew_ms`,
    `:replay_ttl_ms`, `:vault_master_key`) validate per their table rows.
  - Tests: negative (per kept-key validation rule), malformed.
  - Done: configuration validation runs from `SigilGuard.Runtime`; tightened
    the public config surface by deleting removed v2 accessors
    (`backend`, `protocol_profile`, and all `registry_*` readers), removing
    backend-selector examples from ExDoc, and keeping only v3 schema-backed
    readers. Config tests now assert kept-key defaults/validation, removed
    key/value `ConfigError` behavior, malformed values, cross-option failure,
    and absence of legacy accessor exports.
- [x] M6.09 Removed-key error matrix.
  - Spec: `SP.01` - Removed Keys; `SP.12` - V3 Removal Map.
  - AC: `:backend`, `:protocol_profile`, all nine `registry_*` keys, and
    the `scanner_patterns: :registry` value each raise
    `SigilGuard.ConfigError` at boot naming the key and
    `MIGRATING-1.0.md`.
  - Tests: negative (one boot test per removed key/value).
  - Done: added a boot-time matrix in `ConfigTest` for `:backend`,
    `:protocol_profile`, all nine `registry_*` keys, and
    `scanner_patterns: :registry`. Each case clears v3 config, injects the
    removed key/value, starts `SigilGuard.Runtime`, and asserts a
    `SigilGuard.ConfigError` with the offending key, reason
    `:legacy_contract_removed`, and `MIGRATING-1.0.md` in the message.
- [x] M6.10 D13 policy filename rename verification.
  - Spec: `docs/specs/SP.11-repo-policy-kernel-contracts.md` - V3 Policy
    Filenames (D13); `SP.04` - Policy Filenames.
  - AC: with M4.06 shipped, every legacy filename
    (old SIGIL-name variants) produces
    `{:error, {:legacy_policy_filename, found, use}}` and no silent
    fallback path exists anywhere; `MIGRATING-1.0.md` carries the four
    positional rename rows.
  - Tests: negative (all four legacy names), conformance.
  - Done: aligned `SigilGuard.RepoPolicy.find_file/2` with the D13 v3
    candidate names, added pre-selection legacy filename rejection for all four
    old `SIGIL` paths, and verified both `find_file/2` and `load/2` return
    `{:error, {:legacy_policy_filename, found, use}}`. Added coverage that a
    legacy file is not used as a fallback or accepted beside a v3/explicit
    candidate, and added the four-row filename migration table to
    `MIGRATING-1.0.md`.
- [x] M6.11 Remove finch and the `SigilGuard.Finch` pool.
  - Spec: `SP.12` - Dependency Removal (D9); `SP.05` -
    SigilGuard.HTTPClient Behaviour (D9).
  - AC: `{:finch, _}` leaves `mix.exs`; the pool leaves the application
    supervision tree; zero finch references remain in the runtime tree;
    the anchor store runs solely on `SigilGuard.HTTPClient` (M5.11); a
    reference finch adapter remains documentation only.
  - Tests: negative (boot without finch), no-network sweep stays green.
  - Done: removed the direct `:finch` runtime dependency from `mix.exs` and
    replaced the test-support Finch adapter/pool with a `SigilGuard.TestHTTPClient`
    adapter over Erlang `:httpc`. Extended removal coverage to assert no direct
    `:finch` dependency remains, the application supervisor has no
    `SigilGuard.Finch` child, and runtime source has no `Finch.` or
    `SigilGuard.Finch` callsite while the anchor HTTP store still runs through
    `SigilGuard.HTTPClient`.
- [x] M6.12 Runtime dependency-set assertion test.
  - Spec: `SP.12` - Dependency Removal (D9).
  - AC: a permanent test fails whenever the runtime dependency set differs
    from the intended minimal set (`:telemetry`, `:nimble_options`,
    `:jason`) plus OTP/stdlib applications; dev and test deps are exempt;
    adding a runtime dep requires updating this test and a D9-style record.
  - Tests: the assertion itself plus a negative fixture proving it trips.
  - Done: added `SigilGuard.RuntimeDependencySetTest`, which computes the
    production runtime dependency closure from `mix.exs` plus `mix.lock` and
    pins it to `:jason`, `:nimble_options`, and `:telemetry`. The same test
    pins OTP `extra_applications` to `:crypto` and `:logger`, exempts dev/test
    deps through production-only filtering, and includes a synthetic
    extra/missing dependency fixture proving the assertion reports drift.
- [x] M6.13 `MIGRATING-1.0.md` skeleton with the dependency update example.
  - Spec: `SP.12` - V3 Removal Map; `SP.01` - Migration: Envelope To
    Attestation.
  - AC: the guide exists with section structure covering every mapping
    below; includes the `{:sigil_guard, "~> 0.2"}` to
    `{:sigil_guard, "~> 1.0"}` example.
  - Validation: M6.24 completeness script; link check.
  - Done: expanded `MIGRATING-1.0.md` with the v2-to-v3 dependency update
    example, rc exact-pin warning, migration checklist, and stable section
    skeletons for policy filenames, MCP trust metadata, confirmation metadata,
    registry-to-trust-bundle mappings, envelope-to-attestation, profile-to-
    TrustProfile, configuration keys, expected error changes, and version
    pinning.
- [x] M6.14 MIGRATING: `_sigil` to `_agent_trust` before/after examples.
  - Spec: `docs/specs/SP.08-mcp-gateway-and-confirmation-contracts.md` -
    Metadata Namespace.
  - AC: literal before/after payload examples; the mixed-traffic
    transition note lives only here.
  - Validation: completeness script; vocabulary scan exemption honored.
  - Done: replaced the `MIGRATING-1.0.md` trust metadata placeholder with
    literal JSON-RPC before/after examples mapping `_sigil` envelope metadata to
    `_agent_trust` DSSE Agent Trust metadata under `params`, and documented the
    mixed-traffic rollout rule that v3 treats `_sigil` as ordinary user content
    and must not receive both metadata keys on the same endpoint.
- [x] M6.15 MIGRATING: `_sigil_confirmation` to `_agent_confirmation`
      before/after examples.
  - Spec: `SP.08` - Metadata Namespace.
  - AC: literal before/after examples including the `:confirmation_token`
    option path.
  - Validation: completeness script.
  - Done: replaced the `MIGRATING-1.0.md` confirmation metadata placeholder with
    literal JSON-RPC before/after examples mapping `_sigil_confirmation` to
    `_agent_confirmation` under `params`, documented the digest-strip behavior,
    and added the out-of-band `:confirmation_token` option path for confirmed
    request, signed-confirmed request, and confirmed-result helpers.
- [x] M6.16 MIGRATING: `Registry.fetch_bundle/1` to `TrustBundle.load/1`.
  - Spec: `SP.12` - V3 Removal Map.
  - AC: code-level mapping with source construction
    (`{:file, _}`/`{:priv, _, _}`/`{:binary, _}`) guidance.
  - Validation: completeness script.
  - Done: expanded the `MIGRATING-1.0.md` Fetch Bundle section with a
    `Registry.fetch_bundle/1` before snippet and `TrustBundle.load/1` after
    snippets for `{:file, path}`, `{:priv, app, rel}`, and `{:binary, bytes}`.
    The guidance states that host-owned transport supplies remote bytes outside
    SigilGuard and that v3 does not fetch bundles from a registry.
- [x] M6.17 MIGRATING: `Registry.resolve_key/2` and `resolve_did/2` to
      trust-bundle issuer lookup.
  - Spec: `SP.12` - V3 Removal Map.
  - AC: issuer lookup via verified bundle roles; host-auth pointer for DID
    flows.
  - Validation: completeness script.
  - Done: expanded `MIGRATING-1.0.md` with `Registry.resolve_did/2` and
    `Registry.resolve_key/2` before snippets, host-auth guidance for DID/actor
    flows, verified `TrustBundle.identity_issuers/1` issuer checks, and
    explicit key material construction from verified bundle `keys`, root
    keyids, and delegated role keyids for `Attestation.verify/3`.
- [x] M6.18 MIGRATING: `Envelope.sign/verify` to `Attestation.sign/verify`
      mapping table.
  - Spec: `SP.01` - Migration: Envelope To Attestation.
  - AC: the field mapping table is reproduced 1:1; both known consumer
    call-site shapes get exact replacement snippets.
  - Validation: completeness script.
  - Done: reproduced the SP.01 Envelope-to-Attestation table 1:1 in
    `MIGRATING-1.0.md`, including the verdict mapping note. Added exact
    replacement snippets for signing and attaching tool-request metadata
    (`Envelope.sign/3` + `_sigil` to `Attestation.from_decision/3` +
    `Attestation.sign/3` + `Attestation.attach/2`) and for verifying attached
    metadata (`Envelope.verify/2` to `Attestation.fetch/1` +
    `Attestation.verify/3` with trust material and digest options).
- [x] M6.19 MIGRATING: `Profile` to `TrustProfile`.
  - Spec: `SP.01` - Public Modules Removed In V3.
  - AC: function-level mapping; profile id constant migration noted.
  - Validation: completeness script.
  - Done: added a function-level `SigilGuard.Profile` to
    `SigilGuard.TrustProfile` migration table in `MIGRATING-1.0.md`, including
    removed/no-shim rows for legacy normalization, wire-verdict compatibility,
    blocked-reason compatibility, and registry identity endpoints. Documented
    `SigilGuard.TrustProfile.profile_id/0` as the v3 profile id constant
    replacement for `:protocol_profile`.
- [x] M6.20 MIGRATING: config migration table.
  - Spec: `SP.01` - V3 Configuration Surface (Removed Keys).
  - AC: every removed key row with its replacement (or "none") matching
    the SP.01 table verbatim.
  - Validation: completeness script.
  - Done: replaced the `MIGRATING-1.0.md` configuration placeholder with the
    SP.01 removed-key table, including `:backend`, `:protocol_profile`, all
    `registry_*` groups, and the `scanner_patterns: :registry` value. The
    section documents `SigilGuard.ConfigError` with reason
    `:legacy_contract_removed`, kept v3 keys, and `:unknown_config_key` for
    unrecognized keys.
- [x] M6.21 MIGRATING: expected error-change table.
  - Spec: `SP.01` - Error Handling; `SP.02` - Error Handling (reconciled
    atoms).
  - AC: old-to-new atom rows (`:rollback_detected` to
    `:sequence_below_floor`, `:expired_bundle` to `:bundle_expired`,
    `:unknown_issuer` to `:unknown_key_id`, `:invalid_schema`/
    `:invalid_bundle` to `:invalid_bundle_format`, `:missing_signature`/
    `:unsigned_bundle` to `:invalid_envelope`) plus the new
    `SigilGuard.ConfigError` boot behavior.
  - Validation: completeness script.
  - Done: replaced the `MIGRATING-1.0.md` Error Changes placeholder with the
    reconciled old-to-new atom table for rollback, expiry, issuer/key,
    invalid-schema/bundle, and unsigned/missing-signature cases. Documented
    boot-time `SigilGuard.ConfigError` behavior for removed keys
    (`:legacy_contract_removed`) and unknown keys (`:unknown_config_key`), both
    naming `MIGRATING-1.0.md`.
- [x] M6.22 MIGRATING: pin note for v2 users.
  - Spec: `SP.12` - Release Sequence (D11).
  - AC: states that `~> 0.2` users never auto-upgrade to v3 and that
    `~> 1.0` is the explicit 1.0 release-line dependency.
  - Validation: completeness script.
  - Done: expanded the `MIGRATING-1.0.md` Version Pinning section to state
    that `~> 0.2` remains on the v2 line and `~> 1.0` is the 1.0 release-line
    dependency requirement.
- [x] M6.23 CHANGELOG breaking-change section.
  - Spec: `SP.12` - Release Sequence (D11).
  - AC: a breaking-change section enumerates removals with MIGRATING
    anchors; git_ops conventions untouched (generated entries are not
    hand-edited elsewhere).
  - Validation: link check; completeness script.
  - Done: added a manual `Unreleased Breaking Changes For 1.0.0` section above
    the git_ops `<!-- changelog -->` marker, leaving generated entries
    untouched. The section enumerates registry, envelope, metadata, profile,
    config, policy filename, Finch dependency, error atom, and version-pinning
    breaks with anchors into `MIGRATING-1.0.md`.
- [x] M6.24 Migration completeness-gate script.
  - Spec: `SP.12` - Acceptance Criteria.
  - AC: a repo script cross-references the M6 deletion diff (removed
    modules, functions, config keys, filenames) against `MIGRATING-1.0.md`
    and fails on any unmapped removal; it also link-checks the migration
    doc; wired into CI for the M6 branch onward.
  - Tests: fixture-driven script test (unmapped removal fails; mapped
    passes).
  - Done: added `mix sigil.migration_gate`, which statically checks required
    M6 removed modules, functions, config keys, and policy filenames against
    `MIGRATING-1.0.md`, validates local migration-doc links and anchors, and is
    wired into the CI docs job. Added focused tests for a clean guide, missing
    mapping failure, broken-anchor failure, and rejected task arguments.
- [x] M6.25 Remove legacy `_sigil*` reading; strip rule reduces to the six
      SP.01 keys.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - Implementation
    Roadmap (M6); `SP.01` - Metadata Strip Rule.
  - AC: the gateway no longer reads `_sigil`/`_sigil_confirmation`; the
    digest strip set is exactly SP.01's six keys; mixed-traffic behavior
    is documented only in `MIGRATING-1.0.md`.
  - Tests: negative (legacy metadata is inert), property (digest
    stability), conformance.
  - Done: removed `_sigil` and `_sigil_confirmation` fetch/strip aliases from
    `Attestation`, `ToolGateway`, and `MCP.Gateway` base paths; converted
    confirmation and signed-gateway tests to `_agent_*`; added explicit inert
    legacy metadata coverage and digest tests that keep SP.01 metadata
    digest-neutral while treating `_sigil*` as ordinary payload content.
- [x] M6.26 README rewrite: installation, examples, configuration.
  - Spec: `SP.01` - V3 Configuration Surface; `SP.14` - Release Handoff.
  - AC: installation snippet says `{:sigil_guard, "~> 1.0"}`; MCP examples
    are replaced with Agent Trust attestation examples; the configuration
    table lists exactly the SP.01 kept keys.
  - Validation: docs vocabulary scan; `mix docs`; README snippets compile
    as doctests where applicable.
  - Done: updated the README tagline and navigation, kept the 1.0 dependency
    snippet, added `ToolGateway` Agent Trust examples for manifest guarding,
    `_agent_trust` attestation attachment, and `_agent_confirmation`
    confirmations, and added the closed v3 configuration table from the
    validated application surface.
- [x] M6.27 README rewrite: profile section and legacy-language cleanup.
  - Spec: `SP.01` - V3 Position; `SP.12` - V3 Removal Map.
  - AC: the protocol-profile section becomes an Agent Trust Profile
    section; Rust/NIF backend references are gone; the historical upstream
    link remains only as historical context; registry cache prose is
    replaced by trust-bundle cache docs.
  - Validation: vocabulary scan; forbidden-terms scan; link check.
  - Done: added an Agent Trust Profile section with the v3 profile id,
    `_agent_trust`/`_agent_confirmation` metadata, and SP.01 strip behavior;
    documented the per-boot trust-bundle ETS cache and durable signed-bundle
    source of truth; removed the remaining Finch example from README extension
    prose; verified forbidden terms and local README links.
- [x] M6.28 Package metadata cleanup: hosted-registry language removed.
  - Spec: `SP.12` - V3 Removal Map; `SP.14` - Release Handoff And
    Listings.
  - AC: `mix.exs` package description/links carry no hosted-registry or
    NIF language; metadata matches the v3 positioning.
  - Validation: `mix hex.build` dry inspection; vocabulary scan.
  - Done: rewrote the Hex package description around the v3 in-process Agent
    Trust positioning, replaced the historical upstream package link with
    documentation and migration-guide links, removed a stale empty registry
    directory from the package file list, and verified `mix hex.build`
    inspection plus package-metadata vocabulary scan.
- [x] M6.29 Reference-consumer upgrade-branch validation (tier-2 gate).
  - Spec: `SP.12` - Release Sequence (D11); `SP.07` - Stability
    Guarantees (D17).
  - AC: an upgrade branch of the reference consumer builds against this
    repo as a path dependency applying ONLY `MIGRATING-1.0.md` steps; the
    observed diff matches the expected shape: exactly two `_sigil` call
    sites change (tool-args metadata attach and socket auth) plus dropped
    registry/NIF config keys; its three sigil-prefixed boot keys are
    untouched.
  - AC: its full test suite and its security-conformance acceptance tests
    (identity spoofing, repudiation, communications poisoning) pass.
  - Validation: gate record in the M6 notes; any uncovered step spawns an
    M6.30 item.
  - Done: created a local reference-consumer upgrade branch
    against this repo as a path dependency, applied only migration-guide
    surface changes, and verified the expected migration shape: dependency
    pin moved to a path dependency, `_sigil` metadata moved to Agent Trust
    attachment/auth, `SigilGuard.Envelope` usage moved to
    `Attestation.from_decision`/`Attestation.sign`/`Attestation.verify`
    through the consumer's signer wrapper, removed registry/NIF config, and
    left the three sigil-prefixed boot keys untouched. Validation passed:
    `mix compile --warnings-as-errors`; focused signer/socket plus
    security-conformance identity-spoofing, repudiation, and
    communications-poisoning tests; full reference-consumer `mix test`
    (`23422 passed`, including `79` doctests and `44` properties, `295`
    excluded); and daemon boot smoke (`10 passed`). Consumer-local contract
    drift found by the full suite was fixed on the validation branch and did
    not add new SigilGuard migration steps.
- [x] M6.30 Fold reference-consumer findings back into MIGRATING.
  - Spec: `SP.12` - Acceptance Criteria.
  - AC: every migration step discovered during M6.29 that was missing from
    `MIGRATING-1.0.md` is added; the M6.24 script and M6.29 build are
    re-run green afterward.
  - Validation: completeness script green on the updated doc.
  - Done: folded the reference-consumer upgrade findings into
    `MIGRATING-1.0.md`: local path-dependency validation, the two observed
    `_sigil` migration sites (tool-call metadata and socket/session auth), and
    the rule that host-owned sigil-prefixed boot keys stay untouched unless
    they configure SigilGuard itself. The successful M6.29 rerun found no
    additional SigilGuard migration-guide gaps.
- [x] M6.31 CLAUDE.md final flip and docs/README v3 diagrams.
  - Spec: this file - Closed Decisions; `SP.01` - Public API Surface.
  - AC: CLAUDE.md rule 3 names the `_agent_trust`/`_agent_confirmation`
    contracts as the compatibility surface; the architecture section drops
    Registry-era wording; `docs/README.md` diagrams show the v3 module
    topology.
  - Validation: docs lint (M0.22) green; vocabulary scan clean.
  - Done: flipped CLAUDE.md to name the v3 Agent Trust compatibility surface
    (`_agent_trust`, `_agent_confirmation`, statements, trust bundles,
    manifests, and boundary decisions), removed Registry-era architecture
    wording, and expanded the architecture topology in `docs/README.md` with
    current v3 modules. Verified `mix sigil.docs_lint`, `git diff --check`,
    and a focused vocabulary scan.

## M7 - Integrations And Adoption

> Specs: `SP.14`, `SP.15`. Depends on: M6.
> Exit criteria: `./bin/check` clean; M1.02 conformance green;
> all five livebooks execute offline; `bench/output/benchmarks.md`
> published with the environment block.

- [x] M7.01 ExDoc cheatsheet.
  - Spec: `docs/specs/SP.14-ecosystem-integrations-and-interoperability.md` -
    ExDoc Artifacts.
  - AC: `guides/cheatsheet.cheatmd` covers gate verdicts, the policy
    grammar, attestation sign/verify calls, and the confirmation flow.
  - Validation: `mix docs` renders without warnings.
  - Done: added `guides/cheatsheet.cheatmd`, wired it into ExDoc extras, and
    covered gate verdict dispatch, the implemented v3 policy-file grammar,
    attestation sign/verify attachment, and action-bound confirmation. Verified
    `git diff --check`, `mix format --check-formatted mix.exs`,
    `mix sigil.docs_lint`, and `mix docs`.
- [x] M7.02 Threat-model guide rendered from R.06.
  - Spec: `SP.14` - ExDoc Artifacts; `R.06` - Control Mapping.
  - AC: `guides/threat-model.md` reproduces the control-mapping table,
    claim-level definitions, and host-owned exclusions in substance; no
    claim exceeds its R.06 claim level.
  - Validation: `mix docs`; claim-level cross-check against R.06.
  - Done: added `guides/threat-model.md`, wired it into ExDoc extras, and
    reproduced the control-mapping table, claim levels, host-owned exclusions,
    and test-family mapping from R.06 in operator-facing form. Verified
    `git diff --check`, `mix format --check-formatted mix.exs`,
    `mix sigil.docs_lint`, `mix docs`, and a claim-column cross-check against
    R.06.
- [x] M7.03 hermes_mcp integration guide.
  - Spec: `SP.14` - Tier 1: hermes_mcp; Per-Target Acceptance.
  - AC: interceptor and middleware/plug placements both shown; the
    anubis_mcp compile variant passes; denials map onto the SP.03 JSON-RPC
    error registry; pinned-version compile validation recorded.
  - Validation: guide example compiles warnings-as-errors at its pin.
  - Done: added the ExDoc guide with `hermes_mcp` 0.14.1 and `anubis_mcp`
    1.6.2 pins, interceptor-style request/result placement, Hermes component
    registration, Plug/Phoenix placement, JSON-RPC denial mapping, and the
    Anubis component variant. Verified `mix compile --warnings-as-errors` in
    scratch Hermes and Anubis projects plus `git diff --check`,
    `mix format --check-formatted mix.exs`, `mix sigil.docs_lint`, and
    `mix docs`.
- [x] M7.04 Jido integration guide.
  - Spec: `SP.14` - Tier 1: Jido; Per-Target Acceptance.
  - AC: denial surfaces as a Jido action error without raising; `actor` is
    populated from the agent identity; pinned compile validation recorded.
  - Validation: guide example compiles at its pin.
  - Done: added `guides/integrations/jido.md` with the `jido` 2.3.2 pin,
    a guarded action that threads `:agent_id` into the SigilGuard actor
    boundary, normal Jido `{:error, reason}` denial handling, result-gating
    guidance, and validation procedure. Verified the guarded action in a
    scratch project with `mix compile --warnings-as-errors`, plus
    `git diff --check`, `mix format --check-formatted mix.exs`,
    `mix sigil.docs_lint`, and `mix docs`.
- [x] M7.05 LangChain/ReqLLM integration guide.
  - Spec: `SP.14` - Tier 1: LangChain Elixir And ReqLLM.
  - AC: request and result sides both gated; the ReqLLM pipeline-step
    variant appears in the same guide; pinned compile validation recorded.
  - Validation: guide example compiles at its pin.
  - Done: added `guides/integrations/langchain-reqllm.md` with resolved
    `langchain` 0.8.14 and `req_llm` 1.17.1 pins, a shared guarded tool
    module for request/result gating, LangChain `Function` registration,
    ReqLLM `Tool` execution, pipeline-step placement, and denial handling.
    Verified the shared examples in a scratch project with
    `mix compile --warnings-as-errors`, plus `git diff --check`,
    `mix format --check-formatted mix.exs`, `mix sigil.docs_lint`, and
    `mix docs`.
- [x] M7.06 Tidewave gating guide with shipped example policy.
  - Spec: `SP.14` - Tier 1: Tidewave; Per-Target Acceptance.
  - AC: the shipped policy blocks eval-class tools, requires approval for
    repo writes, allows schema/doc reads; the guide states Tidewave is
    dev-only and the guard is defense in depth; `examples/tidewave/`
    carries the policy file.
  - Validation: guide example compiles at its pin; policy fixture parses.
  - Done: added `guides/integrations/tidewave.md`, wired it into ExDoc,
    shipped `examples/tidewave/SIGILGUARD_POLICY`, and documented the
    dev-only defense-in-depth placement. Verified the Tidewave Plug wrapper in
    a scratch project against `tidewave` 0.6.1 / `bandit` 1.12.0 with
    `MIX_ENV=dev mix compile --warnings-as-errors`; verified the policy parses
    and evaluates eval-class tools to `:block`, repo writes to `:confirm`, and
    docs/schema reads to `:allow`; also ran `git diff --check`,
    `mix format --check-formatted mix.exs`, `mix sigil.docs_lint`, and
    `mix docs`.
- [x] M7.07 Livebook: quick start.
  - Spec: `SP.14` - Livebooks.
  - AC: `notebooks/quick-start.livemd` covers install, first scan, gate
    verdicts, and redaction with a Run in Livebook badge.
  - Validation: executes top-to-bottom offline via local-path
    `Mix.install` (M7.12).
  - Done: added `notebooks/quick-start.livemd` with a Run in Livebook badge,
    local-path `Mix.install`, first scan, redaction, gate verdict, and
    `ToolGateway` examples. Manually ran the equivalent cells offline with
    `mix run`; M7.12 will replace this with the notebook runner.
- [x] M7.08 Livebook: policy and lethal trifecta.
  - Spec: `SP.14` - Livebooks; `SP.04` - Dataflow Rules And Lethal
    Trifecta.
  - AC: `notebooks/policy-and-lethal-trifecta.livemd` executes the R.06
    row-10 trifecta rule against live policy evaluation.
  - Validation: offline execution (M7.12).
  - Done: added `notebooks/policy-and-lethal-trifecta.livemd` with a Run in
    Livebook badge, local-path `Mix.install`, an inline v3 policy, row-10
    block behavior, high-trust confirmation, and public model-bound allow
    behavior. Manually ran the equivalent cells offline with `mix run`; M7.12
    will replace this with the notebook runner.
- [x] M7.09 Livebook: audit export and proofs.
  - Spec: `SP.14` - Livebooks; `SP.05` - Inclusion And Consistency Proofs.
  - AC: `notebooks/audit-export-and-proofs.livemd` walks chain,
    checkpoint, inclusion proof, and signed-export verification.
  - Validation: offline execution (M7.12).
  - Done: added `notebooks/audit-export-and-proofs.livemd` with a Run in
    Livebook badge, local-path `Mix.install`, signed audit-chain setup,
    checkpoint verification, inclusion and consistency proof verification,
    signed export verification with anchor evidence, and a committed-HMAC
    tamper check. Manually ran the equivalent cells offline with `mix run`;
    M7.12 will replace this with the notebook runner.
- [x] M7.10 Livebook: hermes integration stub.
  - Spec: `SP.14` - Livebooks (hermes stub rule).
  - AC: `notebooks/hermes-integration.livemd` exercises the interceptor
    contract against an in-notebook stub shaped like the pinned interface;
    it MUST NOT fetch `hermes_mcp` (real wiring lives in M7.03).
  - Validation: offline execution (M7.12).
  - Done: added `notebooks/hermes-integration.livemd` with a Run in Livebook
    badge, local-path `Mix.install`, a Hermes-shaped frame/component stub, a
    SigilGuard request/result interceptor, allowed-call behavior, result
    redaction, and JSON-RPC denial mapping for unknown manifests. Manually ran
    the equivalent cells offline with `mix run`; M7.12 will replace this with
    the notebook runner.
- [x] M7.11 Livebook: threat scenarios.
  - Spec: `SP.14` - Livebooks; `R.06` - Test Families.
  - AC: `notebooks/threat-scenarios.livemd` demonstrates selected TM
    families (tool poisoning, rug pull, schema injection) end to end.
  - Validation: offline execution (M7.12).
  - Done: added `notebooks/threat-scenarios.livemd` with a Run in Livebook
    badge, local-path `Mix.install`, pinned manifest loading, tool-poisoning
    digest rejection, rug-pull list refresh rejection, manifest-bound approval
    invalidation after drift, schema-injection confirmation, and undisclosed
    schema-injection fail-closed behavior. Manually ran the equivalent cells
    offline with `mix run`; M7.12 will replace this with the notebook runner.
- [x] M7.12 Livebook offline validation script.
  - Spec: `SP.14` - Livebooks (validation rule).
  - AC: a script runs every notebook's code cells via `Mix.install` on the
    local repository path in a network-denied environment and fails on any
    error; wired into CI or the release checklist.
  - Tests: script test (a failing cell fails the run; clean run passes).
  - Done: added `mix sigil.livebook_check`, which extracts Elixir cells from
    `notebooks/*.livemd`, executes each notebook in an offline child `elixir`
    process beside the source file so `__DIR__` matches Livebook, and fails on
    the first non-zero notebook execution. Added fixture-driven task tests for
    clean notebooks, failing cells, selected paths, missing files, and cell
    extraction. Verified `mix test test/mix/tasks/sigil_livebook_check_test.exs`
    and `mix sigil.livebook_check`.
- [x] M7.13 Benchmark corpus and harness matrix (BM.01-BM.08).
  - Spec: `docs/specs/SP.15-benchmark-methodology-and-baselines.md` -
    Scenario Matrix.
  - AC: `bench/corpus.exs` generates committed corpora under
    `bench/corpus/` from the fixed seed (regeneration byte-identical;
    hit counts asserted before timing); all eight scenarios run under
    Benchee (`warmup: 2`, `time: 5`, `memory_time: 2`) with `--smoke` and
    JSON output; the environment block auto-renders into
    `bench/output/benchmarks.md`.
  - Tests: corpus determinism test, hit-count precondition, `mix bench
    --smoke` in CI.
  - Done: replaced the stale benchmark harness with the BM.01-BM.08 SP.15
    matrix on live 1.0 APIs, added deterministic committed corpora plus the
    trust-bundle fixture under `bench/corpus/`, wrote
    `bench/output/benchmarks.json`, prepended the required environment block
    to `bench/output/benchmarks.md`, and wired `MIX_ENV=dev mix bench
    --smoke` into CI. Added focused tests for byte-identical corpus
    regeneration, hit-count preconditions, smoke/full Benchee settings, and
    scenario coverage. Verified `mix test test/sigil_guard/bench_test.exs`
    and `mix bench --smoke`.
- [x] M7.14 `bench/compare.exs` regression gate and committed baseline.
  - Spec: `SP.15` - CI Regression Thresholds.
  - AC: `bench/baseline.json` is committed with its environment block;
    `compare.exs` fails on >20% median regression or a missing baseline
    scenario, passes new scenarios, and is binding only on a matching
    runner class; the baseline refresh procedure is documented in-repo.
  - Tests: fixture test (25% regression fails; 15% passes; missing
    scenario fails); JSON shape test against the data model.
  - Done: added `bench/compare.exs` with schema validation, runner-class
    matching, >20% median regression failure, missing-run-scenario failure,
    and informational new-scenario / runner-mismatch reporting. Committed
    `bench/baseline.json`, documented the three-run baseline refresh
    procedure in `bench/README.md`, and wired `mix run bench/compare.exs`
    into CI after the smoke run. Added fixture tests for 25% fail, 15% pass,
    missing scenario fail, new scenario pass, runner mismatch, and committed
    JSON shape. Verified `mix test test/sigil_guard/bench_compare_test.exs
    test/sigil_guard/bench_test.exs` and `mix run bench/compare.exs`.
- [x] M7.15 Post-rewire full benchmark run published.
  - Spec: `SP.15` - Scenario Matrix; Environment Disclosure Format.
  - AC: the full matrix runs after the v3 gateway/scanner rewiring and the
    results land in `bench/output/benchmarks.md` with the environment
    block; numbers are labeled measured values, not ratified SLO bounds.
  - Validation: published file carries all eight scenarios and the block.
  - Done: ran the full SP.15 matrix with Benchee `warmup: 2`, `time: 5`,
    and `memory_time: 2`; regenerated `bench/output/benchmarks.md` and
    `bench/output/benchmarks.json` with the environment block, all BM.01
    through BM.08 scenarios, memory measurements, and measured-value
    labeling. Refreshed `bench/baseline.json` from the full measured run and
    verified `mix run bench/compare.exs`.
- [x] M7.16 llm-guard scanner-scope comparison.
  - Spec: `SP.15` - Cross-Ecosystem Comparison Rules.
  - AC: comparison covers `SigilGuard.scan/1` versus llm-guard input
    scanners only, same machine/corpus/run, versions and configuration
    disclosed, deterministic and ML paths labeled, corpus published for
    reproduction.
  - Validation: comparison artifact satisfies every fairness rule.
  - Done: added `bench/llm_guard_compare.exs` and
    `bench/llm_guard_compare.py`, ran SigilGuard and llm-guard 0.3.16 input
    scanners on the same committed `bench/corpus/` files in one local run,
    and published `bench/output/llm_guard_comparison.{json,md}`. The artifact
    discloses hardware, Elixir/OTP, Python, llm-guard version, scanner classes
    and configuration, labels deterministic paths, states the ML path is not
    measured for this synthetic secret-scanning corpus, and excludes gate,
    attestation, bundle, audit, and policy timings. Added an artifact-shape
    fairness test and verified `mix run bench/llm_guard_compare.exs`.
- [x] M7.17 SECURITY.md.
  - Spec: `SP.14` - SECURITY.md.
  - AC: states supported versions (latest 1.x; final 0.2.x gets security
    fixes for six months after GA), private-vulnerability-report channel,
    the 72 h / 7 d / 90 d response SLO, and the pointer to SP.02's
    emergency rotation ceremony as the signer-compromise runbook.
  - Validation: link check; policy renders on the repo security tab.
  - Done: added `SECURITY.md` with supported-version policy for latest `1.x`
    and six months of final `0.2.x` fixes after `1.0.0` GA, GitHub private
    vulnerability reporting instructions, 72 h / 7 d / 90 d response targets,
    scope boundaries, and the SP.02 signer-compromise rotation pointer.
    Verified `git diff --check` and `mix sigil.docs_lint`.
- [x] M7.18 Conference-ready Livebook tutorial track.
  - Spec: `SP.14` - Livebooks; `R.07` - 2026-08-19 Livebook Delivery
    Refresh.
  - AC: `notebooks/README.md` maps the complete public capability groups to a
    self-study path and talk run sheets; every notebook uses a local
    lock/config-aware setup with a published-Hex fallback; the expanded track
    covers the gateway trust flow, MCP v2/Apps, streaming and extension seams,
    trust bundles/identity/vault, A2A, and audit assessment projection; the AI
    chapter offers a deterministic offline replay and an optional ReqLLM 1.20
    tool proposal using a Livebook secret, with both paths crossing the same
    gate before any callback runs.
  - Validation: `mix sigil.livebook_check`; Run in Livebook links and local
    setup paths checked; AI offline mode passes without provider dependencies
    or network; `mix docs` renders the tutorial catalog.
  - Done: expanded `notebooks/` into an eleven-chapter self-study, workshop,
    and conference-talk track covering every public capability group. Added a
    deterministic adversarial AI replay plus optional ReqLLM 1.20 tool
    proposal, both routed through the same host-owned SigilGuard gate. Packaged
    every notebook in the Hex archive and ExDoc, added offline-environment
    regression coverage, and verified all eleven notebooks plus the complete
    repository quality gate.

## M7A - Pre-Release Audit Hardening

> Source: 2026-07-07 pre-release audit (three-track sweep: security and
> anti-patterns across all lib modules; HexDocs, docs, and naming; tests,
> fixtures, performance, and release readiness). Verified against Closed
> Decisions - nothing here reopens D1-D19. Depends on: M7. M7A.01, M7A.02,
> and M7A.03 block M8 exit; the rest should land before GA but do not gate
> publication mechanics.
> Audit verdicts recorded, no task needed: `test/fixtures/` depth is
> justified (golden-vector triplets, generator-driven, byte-identical
> regeneration tests) and stays; README architecture narrative matches
> `lib/`; crypto discipline (constant-time compares, verify-before-parse,
> pinned Ed25519, strong randomness, no network in decision paths) verified
> clean.

- [x] M7A.01 Make replay-store check-and-put atomic.
  - Spec: `SP.01` - replay defense; audit finding (TOCTOU).
  - AC: `SigilGuard.ReplayStore.check_and_put/3` uses `:ets.insert_new/2`
    (or equivalent atomic claim) so two concurrent calls with the same
    identity/nonce cannot both return `:ok`; expired-entry re-claim stays
    correct; `prune_expired/1` no longer runs a full-table
    `:ets.select_delete` on every call (amortized: interval, probabilistic,
    or on-hit pruning).
  - Tests: dedicated `replay_store_test.exs` (currently missing) with a
    concurrent-replay race test (many tasks, one nonce, exactly one `:ok`),
    TTL expiry re-claim, and prune behavior; confirmation and attestation
    `consume: true` paths re-exercised.
  - Done: rewrote `check_and_put/3` around atomic `:ets.insert_new/2`,
    added exact-key expired reclaim, and changed full-table pruning to an
    interval-amortized pass. Added `test/sigil_guard/replay_store_test.exs`
    covering concurrent claims, TTL reclaim, and amortized pruning. Verified
    `mix test test/sigil_guard/replay_store_test.exs
    test/sigil_guard/confirmation_test.exs
    test/sigil_guard/attestation_sign_verify_test.exs` and
    `mix compile --warnings-as-errors`.
- [x] M7A.02 Repair the benchmark suite and published benchmark doc.
  - Spec: `SP.15` - Benchmark Methodology; `R.07`.
  - AC: `bench/run.exs` compiles and runs against the 1.0.0 API - the
    removed envelope/registry-bundle scenarios and the nonexistent backend
    envelope calls are rewritten against `SigilGuard.Attestation` and
    `SigilGuard.TrustBundle`; `bench/output/benchmarks.md` is regenerated
    on the 1.0.0 line before it ships as the HexDocs Performance extra; a
    CI or gate step compiles the bench script so it cannot rot again.
    Blocks M8.07 (the SLO matrix cannot run on a bench suite that does not
    compile).
  - Validation: `mix bench` completes; regenerated doc cites only live
    modules; gate step green.
  - Done: replaced the stale benchmark suite with the live BM.01-BM.08
    matrix on `SigilGuard.scan/1`, `Runtime.Gate`, `Runtime.Stream`,
    `Attestation`, `TrustBundle`, audit proof/checkpoint APIs, and
    `ToolGateway`; removed the old envelope/registry-bundle/backend-envelope
    scenarios; regenerated `bench/output/benchmarks.md` from a full measured
    run; and wired `mix bench --smoke` into CI. Verified `mix bench`,
    `mix bench --smoke`, and `mix run bench/compare.exs`.
- [x] M7A.03 Remove the tool-gateway coverage exclusion.
  - Spec: CLAUDE.md rule 9; `SP.03`.
  - AC: `lib/sigil_guard/tool_gateway/base.ex` (1160 lines of shared
    enforcement code) is removed from `coveralls.json` `skip_files` and the
    suite still meets the >= 95% floor; any genuine coverage-attribution
    problem is documented in `coveralls.json` with the exact reason instead
    of a bare skip.
  - Validation: `mix test --cover` >= 95% with the file measured.
  - Done: removed `lib/sigil_guard/tool_gateway/base.ex` from the coverage
    skip list, documented the remaining `test/support/.*` attribution skip in
    `coveralls.json`, and added direct gateway tests for request/result
    confirmation, signed-request fail-closed paths, response metadata
    variants, malformed payload normalization, and streaming responses.
    Verified `mix test --cover` at 95.0% total with
    `lib/sigil_guard/tool_gateway/base.ex` measured at 98.1%.
- [x] M7A.04 Use canonical digests for the runtime-gate context digest.
  - Spec: `SP.04` - boundary decision inputs.
  - AC: `SigilGuard.Runtime.Gate.build_boundary/1` derives `context_digest`
    from a canonical serialization (reuse `SigilGuard.Attestation.Digest`)
    instead of `inspect(context)`, which truncates at the default inspect
    limit and is not version-stable; distinct contexts can no longer
    collide via truncation.
  - Tests: collision regression (two contexts differing only past the old
    truncation horizon produce distinct digests); digest stability vector.
  - Done: changed `SigilGuard.Runtime.Gate` boundary construction to derive
    `context_digest` through `SigilGuard.Attestation.Digest.context_digest/2`
    using the SP.01 statement taxonomy (`:inbound_user` ->
    `:model_ingress`, `:outbound_model` -> `:model_egress`, and
    `:repo_change` preserved). Added hook-observed runtime gate regression
    tests proving the boundary digest matches the canonical attestation digest
    and that two long contexts differing only past the old inspect truncation
    horizon produce distinct digests. Verified
    `mix test test/sigil_guard/runtime/gate_test.exs` and
    `mix test --cover`.
- [x] M7A.05 Align trust-bundle threshold docs with D3 semantics.
  - Spec: `SP.02`; Closed Decision D3 (v1 enforces threshold 1).
  - AC: `SigilGuard.TrustBundle.verify/2` and `TrustBundle.Verify` docs
    state explicitly that the declared role threshold is enforced only with
    `enforce_declared_threshold: true` and that v1 defaults to 1 per D3;
    the option is documented in the options list and the cheatsheet. No
    default behavior change (D3 stays closed).
  - Tests: doc-alignment assertions in the multisig suite (threshold
    ignored by default, enforced with the flag) if not already present.
  - Done: documented the D3 default threshold of 1 and the
    `enforce_declared_threshold: true` opt-in in both trust-bundle verify
    APIs and the README cheatsheet; added doc-alignment assertions proving
    the public docs and README describe the default and opt-in behavior.
- [x] M7A.06 Precompile repo-policy glob segments.
  - Spec: `SP.04`; audit finding (hot-path `Regex.compile!`).
  - AC: `SigilGuard.RepoPolicy.compile/1` precompiles glob segment
    matchers; `segment_matches?/2` never calls `Regex.compile!` during
    evaluation; behavior is byte-identical on the existing policy fixtures.
  - Tests: existing repo-policy suite green; bench scenario (post-M7A.02)
    shows evaluate no longer recompiling.
  - Done: moved repo-policy glob segment regex compilation into
    `compile/1`, stored precompiled path matchers outside canonical policy
    bytes, normalized manually built policy structs, and added regression
    tests proving evaluation no longer contains `Regex.compile!` while
    canonical bytes/digests stay byte-identical.
- [x] M7A.07 Fix HexDocs extras, module groups, and reference warnings.
  - Spec: `SP.06` - docs surface; HexDocs best practice.
  - AC: the architecture page reachable from README (currently
    `docs/README.md`, linked four times but absent from `extras`, so it
    404s on hexdocs.pm) is added to `extras` or moved into a guide page
    with links updated; `SECURITY.md` joins
    `extras` under Reference; every public module appears in
    `groups_for_modules` (currently ~21 ungrouped, including the
    BoundaryPolicy kernel, `ToolGateway`, `Verdict`, `Lifecycle`, `Hooks`,
    `CapabilityManifest`, `AgentTrust`, `AgentCard`, `HTTPClient`,
    `Identity.Static`, and four Audit modules);
    `skip_undefined_reference_warnings` covers the migration guide and
    changelog references to removed modules so `mix docs` is warning-clean.
  - Validation: `mix docs` clean; spot-check rendered nav grouping.
  - Done: added `docs/README.md` as the architecture page and `SECURITY.md`
    to ExDoc extras,
    grouped the full public module surface including Mix tasks, boundary,
    gateway, Agent Trust, audit, identity, lifecycle, and verdict modules,
    skipped removed-module reference warnings for migration/changelog docs,
    and verified `mix docs` warning-clean.
- [x] M7A.08 Correct the Hex package file set.
  - Spec: `SP.12` - release packaging.
  - AC: package `files` ships `guides/`, `SECURITY.md`, and
    `CONTRIBUTING.md`, and stops shipping the internal `docs/` tree (specs,
    research, tasks, templates) - at most the architecture page remains;
    the tarball is inspected to confirm contents.
  - Validation: `mix hex.build` + local tarball listing inspection.
  - Done: changed the package file set to ship `guides/`, `SECURITY.md`,
    `CONTRIBUTING.md`, `AGENTS.md`, `bench/output/benchmarks.md`, and only
    `docs/README.md` from the internal docs tree; built
    `sigil_guard-1.0.0.tar` with `mix hex.build` and inspected the local
    tarball listing without adding release-execution artifacts to source
    control.
- [x] M7A.09 Normalize version vocabulary in reader-facing docs.
  - Spec: `SP.06`; `SP.12`.
  - AC: rendered API docs no longer use internal "v2"/"v3" generation
    labels (`lifecycle.ex`, `sigil_guard.ex`, `decision.ex`, `config.ex`,
    `telemetry.ex` moduledocs); README, CHANGELOG, and MIGRATING-1.0.md
    speak in release-line terms ("0.2.x" vs "1.0"), defining the
    generation label once if kept for internal docs; the CHANGELOG
    Conventional Commits link scheme typo (`Https://`) is fixed and the
    unreleased 1.0.0 section is ready to cut as a dated release entry at
    tag time.
  - Validation: docs grep gate for the old vocabulary in rendered surfaces.
  - Done: converted reader-facing README, CHANGELOG, cheatsheet, and public
    module docs from internal generation labels to 0.2.x/1.0 release-line
    wording, fixed the `Https://` Conventional Commits link, kept the
    migration guide's generation labels only as a one-time historical
    definition, and verified `mix docs` remains warning-clean.
- [x] M7A.10 Anchor validation regexes with `\A...\z`.
  - Spec: `SP.01`/`SP.02` error-handling tables; audit finding.
  - AC: timestamp/hex/id regexes in `trust_bundle/schema.ex`,
    `confirmation.ex`, `agent_card.ex`, `capability_manifest.ex`,
    `attestation/statement.ex`, and `agent_trust.ex` use `\A...\z` anchors
    (matching the existing correct pattern in `audit/proof.ex`) so values
    with trailing newlines no longer pass; `capability_manifest.ex`
    `expires_at` gains a semantic parse check, not regex-only.
  - Tests: malformed-input cases with trailing-newline payloads across the
    six modules.
  - Done: replaced timestamp, digest, nonce, keyid, and integer validators
    in the six audited modules with `\A...\z` anchors, added semantic
    `expires_at` parsing for capability manifests, and added trailing-newline
    and regex-shaped-invalid tests across trust bundles, confirmations,
    agent cards, capability manifests, attestation statements, and Agent
    Trust response verification.
- [x] M7A.11 Minor hardening and hygiene sweep.
  - Spec: audit findings (grouped small items).
  - AC: `SigilGuard.Attestation.attach/2` and `attach_confirmation/2` stop
    embedding `inspect(payload)` in raise messages (truncate or omit -
    payloads may carry secret material); `TrustBundle.Verify` key loading
    handles malformed base64 as a typed error instead of a `MatchError`
    depending on upstream schema ordering, and `positive_integer!/1`'s
    spec matches its behavior; `Backend.impl/0` memoizes custom-backend
    reflection (`Code.ensure_loaded?`/`function_exported?` per call
    today); the near-unused Mox dependency gets an explicit keep-or-drop
    decision recorded.
  - Tests: negative tests for the attach raise paths and malformed key
    material; existing suites green.
  - Done: removed payload/token/envelope inspection from attestation raise
    messages, hardened trust-bundle public-key decoding against malformed
    base64 without `MatchError`, tightened `positive_integer!/1`, memoized
    backend reflection by configured backend, dropped the unused `:mox`
    test dependency, and added focused negative regressions.
- [x] M7A.12 Centralize test fixture path resolution.
  - Spec: audit verdict on `test/fixtures/` layout.
  - AC: the golden-vector triplet layout stays as-is (verdict: depth is
    justified and generator-driven); a small shared fixtures helper in
    `test/support/` replaces the literal relative path strings in
    `test/sigil_guard/threat_model/tm*_test.exs` and other inline
    `Path.expand` call sites, so fixture paths resolve independent of cwd
    and have one owner.
  - Validation: suite green from repo root and from a subdirectory runner.
  - Done: added `SigilGuard.FixturePath` as the single `test/fixtures`
    resolver, migrated threat-model manifest reads and inline fixture roots
    to the helper, removed cwd-relative fixture reads, kept generator-owned
    fixture layouts intact, and added a cwd-changing regression proving the
    helper resolves fixtures from a subdirectory context.
- [x] M7A.13 Remove real-clock sleeps from tests.
  - Spec: CLAUDE.md rule 9 (deterministic security tests).
  - AC: the `Process.sleep(500)` waits in `adaptive_detector_test.exs` and
    `hooks_test.exs` are replaced with injected clocks, telemetry
    assertions, or message-based synchronization; no real-time waits
    remain in the suite outside genuinely time-bound TTL tests that use
    short, bounded budgets.
  - Validation: suite wall-clock drops; repeated CI runs stable.
  - Done: replaced the 500 ms adaptive-detector and hook timeout fixtures
    with message-blocking workers that are killed by the existing bounded
    invocation path, verified the focused suites, and confirmed the only
    remaining `Process.sleep/1` is the short replay-store TTL test.
- [x] M7A.14 Document the gateway layering and add entry-point examples.
  - Spec: `SP.03`/`SP.08`; Closed Decision D14 (facade stays - no rename).
  - AC: one canonical "start here" explanation of the
    `SigilGuard.ToolGateway` (enforcement core) versus
    `SigilGuard.MCP.Gateway` (permanent thin facade) split, cross-linked
    from both moduledocs, the README, and the cheatsheet, resolving the
    current each-points-at-the-other ambiguity; `## Examples` sections
    (doctested where practical) are added to the high-traffic public
    modules currently lacking them (`ToolGateway`, `MCP.Gateway`,
    `Confirmation`, `Attestation`, `TrustBundle`); `audit/logger.ex` gains
    direct unit coverage alongside the M7A.01 replay-store tests.
  - Validation: `mix docs` + doctests green.
  - Done: documented `SigilGuard.ToolGateway` as the enforcement core and
    `SigilGuard.MCP.Gateway` as the permanent MCP transport facade in both
    moduledocs, README, and cheatsheet; added compact entry-point examples
    to `ToolGateway`, `MCP.Gateway`, `Confirmation`, `Attestation`, and
    `TrustBundle`; added direct `Audit.Logger` callback success/error
    coverage; verified `mix docs` and focused gateway/attestation/
    confirmation/trust-bundle/logger tests.
- [x] M7A.15 Make Hex advisory triage executable and current.
  - Spec: `R.07`; CLAUDE.md dependency and quality-gate rules.
  - AC: the canonical clean-clone gate runs both `mix deps.audit` and
    `mix hex.audit`; every ignored Hex advisory has a current, documented
    reachability decision and re-review deadline; a newly published advisory
    fails CI until it is fixed or explicitly triaged.
  - Validation: both advisory commands and `./bin/check` exit zero.
  - Done: added `mix hex.audit` to ExCheck and every documented full-gate
    list; triaged CVE-2026-43971 as test-only and unreachable from SigilGuard;
    recorded the absent fixed release and mandatory pre-release recheck.
- [x] M7A.16 Add reproducible full-history secret scanning.
  - Spec: `SP.05` release and supply-chain controls; `SECURITY.md`.
  - AC: the canonical clean-clone gate scans Git history with a pinned,
    checksum-verified Gitleaks release; CI checks out full history; only exact,
    reviewed synthetic-fixture fingerprints may be ignored.
  - Validation: `./bin/check-secrets`, `actionlint`, and `./bin/check` exit zero.
  - Done: added the portable pinned scanner bootstrap, wired it into ExCheck,
    fetched full history in the CI quality job, and recorded exact fingerprints
    for the 27 reviewed scanner-fixture findings already present in history.
- [x] M7A.17 Fail closed on malformed hook and detector options.
  - Spec: `SP.04` - Hooks Behaviour and Error Handling.
  - AC: malformed option containers, hook lists, detector modules, and timeout
    values never reach `receive ... after`; direct hooks block on blockable
    phases and log on notification phases; policy/runtime entry points emit a
    terminal `:invalid_options` block.
  - Validation: focused hook, adaptive-detector, boundary-policy, and runtime
    gate tests plus `./bin/check` exit zero.
  - Done: validated module-list and BEAM timeout boundaries at every public
    entry point and added direct and integrated negative-path regressions.
- [x] M7A.18 Add focused mutation testing for verdict precedence.
  - Spec: `SP.04` - Decision Combination; resilience-report verification
    quality rule.
  - AC: the canonical gate performs unoptimized code mutation against the
    small, high-risk pure verdict-order primitive and fails below 100%; no
    surviving mutant may invert or weaken strongest-wins behavior.
  - Validation: the focused Muex command and `./bin/check` exit zero.
  - Done: added the dependency-locked Muex gate over `SigilGuard.Verdict`;
    78/78 compilable mutants are killed, 13 invalid mutants are reported, and
    the mutation score is 100%.
- [x] M7A.19 Make runtime-license evidence release-enforced.
  - Spec: `SP.05` - Release Provenance (D15); `R.07` dependency review.
  - AC: every production package in the SPDX SBOM carries the license declared
    by the matching installed Hex artifact; absent, malformed, empty, or
    version-mismatched metadata fails SBOM generation instead of producing
    `NOASSERTION`.
  - Validation: SBOM tests, generation/verification, package gate, and
    `./bin/check` exit zero.
  - Done: bound all three locked runtime packages to their Apache-2.0 Hex
    metadata and added completeness assertions for the generated SPDX document.
- [x] M7A.20 Align hook telemetry with the observability contract.
  - Spec: `SP.04` - Telemetry And Observability.
  - AC: every invoked hook emits one bounded-cardinality outcome event with a
    native-time duration measurement; successful outcomes and fail-closed
    failures are distinguishable without payload or matched-text metadata.
  - Validation: focused hook telemetry tests and `./bin/check` exit zero.
  - Done: normalized success, signal, deny-side, timeout, crash, invalid-result,
    and invalid-option outcomes under `hook_result`; added duration measurements
    and direct success/failure telemetry regressions.
- [x] M7A.21 Execute every shipped Livebook in the canonical gate.
  - Spec: `SP.14`; resilience-report public-contract and deterministic-
    verification hard gates.
  - AC: `./bin/check` executes every Elixir cell from every packaged Livebook
    offline, so a broken conference tutorial fails the same gate as broken API
    documentation.
  - Validation: `mix sigil.livebook_check` and `./bin/check` exit zero.
  - Done: added the existing offline Livebook validator to ExCheck and every
    documented full-gate command list.
- [x] M7A.22 Revalidate public research and specification links.
  - Spec: `SP.05`, `SP.15`, and research source discipline; resilience-report
    public-contract verification rule.
  - AC: reader-facing sources resolve to the current canonical documents or an
    explicitly identified historical/expired artifact; templates do not ship a
    deliberately dead placeholder link.
  - Validation: full Markdown/Livebook link crawl plus `mix docs` exit zero.
  - Done: updated moved SLSA, NIST, IETF, llm-guard, mcp-use, and crate links and
    made the research-template placeholder non-link text.
- [x] M7A.23 Reconcile every telemetry specification with the 1.0 event surface.
  - Spec: `SP.01`, `SP.03`, `SP.04`, `SP.13`; resilience-report comment/spec/
    code agreement and observability rules.
  - AC: no specification promises a retired or never-emitted event family;
    direct pure primitives say so explicitly; policy events carry a measurable,
    common metadata shape; `Telemetry.events/0` remains the exact public list.
  - Validation: telemetry, boundary-policy, hook, and documentation tests plus
    `./bin/check` exit zero.
  - Done: removed stale attestation, tool-gateway, boundary-evaluate, and
    boundary-contract event promises; documented their consolidated owners and
    added the boundary-policy system-time/common-shape regression.
- [x] M7A.24 Emit MCP telemetry after gateway enrichment.
  - Spec: `SP.16` - Telemetry And Observability; resilience-report disconnected-
    observability rule.
  - AC: request/result protocol classification is present on the consolidated
    MCP event for successful and pre-gate-denied calls; raw request/result data
    stays absent; arbitrary protocol/result strings do not become default metric
    dimensions.
  - Validation: gateway and OTel high-cardinality regressions plus
    `./bin/check` exit zero.
  - Done: centralized the bounded MCP metadata allowlist, emitted after top-level
    enrichment, and classified protocol revision/result type as opt-in OTel
    attributes.
- [x] M7A.25 Make policy-loader option validation total and fail closed.
  - `RepoPolicy` and `BoundaryPolicy.File` reject malformed option containers,
    unknown keys, invalid candidate/replacement shapes, and invalid byte limits
    before filesystem access.
  - Non-integer byte limits can no longer weaken the size cap through Erlang
    term ordering.
  - Tests: repo-policy and boundary-policy loader suites cover malformed lists,
    unknown keys, bad shapes, invalid limits, and invalid path/root inputs.
- [x] M7A.26 Fail closed when a release tag is not protected.
  - `sigil_guard.verify_release_ref` requires the workflow-provided
    `github.ref_protected` signal during strict CI identity verification.
  - Release guidance distinguishes code-owned workflow isolation from the
    owner-managed tag ruleset, environment reviewers, tag restrictions, and
    environment-secret configuration required before publication.
  - Tests: exact protected-tag identity succeeds; false or missing protection
    state fails `:unprotected_ref`; `actionlint` validates the workflow binding.

## M8 - Release

> Specs: `SP.12` (Release Sequence (D11)), `SP.15` (SLO Ratification),
> `SP.05` (Release Provenance). Depends on: M6 (M7 required before GA;
> M7A.01-M7A.03 block M8 exit).
> Agent-owned exit criteria: `./bin/check` clean; M1.02 conformance
> green; reference-consumer path-dependency validation green (M6.29); SLOs
> ratified. Publish, push, tag, release-checklist execution, package-artifact
> validation, and production consumer bumps are maintainer-owned operations
> outside this checklist.

- [x] M8.01 Align repository versioning to 1.0.0.
  - Spec: `SP.12` - Release Sequence (D11); `R.07`.
  - AC: `mix.exs` version is `1.0.0`; README and migration dependency
    snippets use `~> 1.0`; the migration guide is named `MIGRATING-1.0.md`;
    release-provenance examples, Agent Trust release fixtures, and package
    metadata all reference `1.0.0`.
  - Validation: package build metadata shows version `1.0.0`; migration and
    docs gates pass; release-vector fixture tests pass.
  - Done: bumped the package version to `1.0.0`, aligned the migration guide
    at `MIGRATING-1.0.md`, updated dependency snippets and release docs to the
    1.0 release line, regenerated Agent Trust release fixtures, and verified
    the focused release/doc gates.
- [x] M8.02 git_ops 1.0.0 resume check.
  - Spec: `SP.12` - Release Sequence (D11).
  - AC: `mix git_ops.release --dry-run` operates normally from the `1.0.0`
    line and does not try to derive a separate major-version jump.
  - Validation: dry-run output archived in the release notes draft.
  - Done: `mix git_ops.release --dry-run` resumes from `1.0.0` and reports
    `1.1.0` as the next normal conventional-commit release.
- [x] M8.03 SLSA L3 provenance and SBOM workflow readiness.
  - Spec: `docs/specs/SP.05-audit-and-release-provenance.md` - Release
    Provenance (D15).
  - AC: the maintainer-triggered 1.0.0 tag workflow verifies exact
    tag/version/SHA identity and produces SLSA v1 provenance via
    `actions/attest` with tarball + SBOM subjects; both SLSA and custom
    `gh attestation verify` checks gate publish; the SP.01 `release` predicate
    directly binds the validated package/version and both artifact names and
    digests, and is attached to both subjects.
  - Tests: Elixir builders and negative verification paths are unit-tested;
    tag execution remains maintainer-owned.
  - Done: `.github/workflows/publish.yml` separates validation/build,
    OIDC-backed attestation, and environment-scoped publication. It verifies
    the exact protected tag and triggering commit, builds the Hex tarball and
    SPDX SBOM after
    `./bin/check`, signs both SLSA and the directly bound release predicate for
    both subjects, and verifies both forms before publication. The Hex-only job
    receives the secret solely for `mix hex.publish`, compares a fresh build to
    the attested tar first, and checks the downloaded registry bytes afterward.
- [x] M8.04 Socket-denying no-network sweep.
  - Spec: `SP.02` - Loading Sources (No-network guarantee); `SP.05` -
    SigilGuard.HTTPClient Behaviour (trust model).
  - AC: a suite-wide sweep proves every scan/gate/policy/attestation/
    bundle/audit decision path opens no sockets (anchor HTTP puts are the
    sole, explicitly host-triggered exception); runs in CI on the release
    branch.
  - Tests: negative (port-list and socket-deny assertions across paths).
  - Done: added `test/sigil_guard/release_no_network_sweep_test.exs` covering
    scanner, boundary policy, runtime gate, attestation statement building,
    trust-bundle verification, and local audit anchor put/fetch/verify under
    unchanged current-process port assertions. Added a static source scan
    proving core decision paths do not directly reference `:httpc`, `:gen_tcp`,
    `:ssl`, or `SigilGuard.HTTPClient`; HTTP anchor-store tests remain the
    explicit host-triggered exception.
- [x] M8.05 Fuzz final pass over attestations, bundles, manifests, and
      policy files.
  - Spec: `SP.01`/`SP.02`/`SP.03`/`SP.04` - Error Handling tables.
  - AC: randomized malformed-input campaigns against every public decode/
    verify entry point produce only taxonomy atoms - no raises, no
    timeouts; corpus seeds are committed for reproduction.
  - Tests: malformed (fuzz harness), negative.
  - Done: added `test/sigil_guard/release_malformed_campaign_test.exs` with
    fixed seeds covering attestation digest/statement/envelope verification,
    Agent Trust predicates, trust-bundle load/verify, capability manifests,
    boundary policy files, repo policy parsing/compilation, and boundary
    evaluation. The campaign exposed and fixed fail-closed malformed-list
    handling in `SigilGuard.Boundary.new/1`, `SigilGuard.BoundaryPolicy.evaluate/2`,
    and `SigilGuard.RepoPolicy.compile/1`.
- [x] M8.06 Telemetry conformance tests for every event family.
  - Spec: `SP.02`/`SP.03`/`SP.04`/`SP.05` - Telemetry And Observability
    tables.
  - AC: every documented event family fires with exactly the documented
    measurement/metadata keys; no undocumented events are emitted; the
    `sigilguard.*` namespace holds everywhere.
  - Tests: telemetry conformance suite (one assertion block per family).
  - Done: removed retired `:registry` and `:envelope` families from
    `SigilGuard.Telemetry.events/0`, updated the module event docs to current
    scan/policy/boundary/runtime/MCP/audit/trust-bundle/Agent Trust families,
    and added exact event-list and legacy-family guards in
    `test/sigil_guard/telemetry_test.exs`.
- [x] M8.07 SLO ratification from 1.0.0 measurements.
  - Spec: `docs/specs/SP.15-benchmark-methodology-and-baselines.md` - SLO
    Ratification.
  - AC: the full matrix runs on the disclosed reference environment at
    1.0.0; SLOs are ratified as measured median and p99 plus 50% headroom
    into SP.15's Success Metrics (bump `updated:`).
  - Validation: SP.15 update commit; published figures cite the ratified
    numbers only.
  - Done: ratified SP.15 from the 2026-07-07 1.0.0 benchmark run on Apple M4
    Max, 16 cores, Elixir 1.20.2 / OTP 29, SigilGuard 1.0.0 (298d787).
    Ratified bounds: BM.03 gate p50 <= 200 us, BM.03 gate p99 <= 250 us,
    BM.01 clean 1 MiB throughput >= 50 MiB/s, and BM.08 gateway median
    overhead <= 40 us.
- [x] M8.08 Dependency-audit posture note.
  - Spec: `SP.12` - Dependency Removal (D9); `R.07`.
  - AC: release notes record the audited posture: runtime deps are the
    intended minimal set (`:telemetry`, `:nimble_options`, `:jason`) chosen
    on merit; integrations and adaptive detectors add no runtime deps
    (docs/optional packages only); `mix deps.audit` clean at tag.
  - Validation: note present; M6.12 assertion green at tag.
  - Done: recorded the runtime dependency posture in `CHANGELOG.md`; verified
    `mix deps.audit` reports no vulnerabilities for the 1.0.0 release line.

## M9 - MCP `2026-07-28` Alignment

> Specs: `SP.16`, `SP.03`, `SP.08`; research: `R.08`. Depends on: M8
> agent-owned release readiness. Publishing, pushing, tagging, and package
> release remain maintainer-owned.

- [x] M9.01 Canonical structured MCP security payload.
  - AC: request/result binding retains keys and every JSON value; correlation
    ids and fixed guard metadata do not affect approval digests.
- [x] M9.02 Legal JSON-RPC rejection registry.
  - AC: statuses map exactly to `-31990..-31984`; no SigilGuard error uses the
    MCP-reserved `-32020..-32099` range.
- [x] M9.03 Protocol version and result discrimination.
  - AC: MCP `2026-07-28` responses insert/preserve `resultType`; legacy
    responses retain legacy shape.
- [x] M9.04 MRTR request/result binding.
  - AC: `inputResponses` and `requestState` changes invalidate approvals;
    input-required results retain their discriminator and are scanned.
- [x] M9.05 Capability-manifest v2 display and UI binding.
  - AC: title, icons, normalized UI URI/visibility, schemas, annotations, and
    security properties participate in the manifest digest.
- [x] M9.06 `x-mcp-header` validation.
  - AC: invalid, duplicate, non-primitive, or sensitive header annotations
    fail closed with typed errors.
- [x] M9.07 MCP Apps caller boundary.
  - AC: app origin normalizes from strings; model/app visibility and same-server
    requirements are enforced before execution.
- [x] M9.08 MCP App resource verification.
  - AC: UI URI, MIME, content digest, CSP domains, permissions, and malformed
    resource shapes fail closed without network or rendering.
- [x] M9.09 Threat-model and integration alignment.
  - AC: session/resumability language is replaced with stateless,
    subscription/list-refresh, explicit-handle, MRTR, and Apps threats; adapter
    guides disclose their protocol era.
- [x] M9.10 Migration, README, changelog, and GitOps release readiness.
  - AC: all intentional 1.0 changes and host responsibilities are documented;
    the changelog marker/config remain compatible with automated git_ops.
- [x] M9.11 Golden vectors and complete regression suite.
  - AC: confirmation/attestation/manifest vectors are regenerated; focused
    tamper, malformed, replay, expiry, quarantine, modern/legacy, and Apps tests
    are green.
- [x] M9.12 Full release quality gate.
  - AC: every `CLAUDE.md` and `done` skill gate passes; coverage remains at
    least 95%; no publish, push, or tag is performed.

## M10 - External Assessment Projection

> References: `docs/specs/SP.17-external-assessment-projection.md`,
> `docs/research/R.10-external-assessment-formats-and-evidence-projection.md`
> Effort: M
> Status: complete
> Dependencies: SP.05, R.10

- [x] M10.01 Host-authorized OSCAL observation projection.
  - AC: `SigilGuard.Assessment.OSCAL.project/2` accepts only a closed host
    context, binds the digest of the exact `Audit.Export.canonical_bytes/1`
    resource, rejects fragment/query-only locators, and emits OSCAL Assessment
    Results v1.2.3 observations with explicit control and subject scope.
  - AC: findings, risks, assessment attestations, satisfaction states, network
    access, clock access, and changes to `Audit.Export` or Agent Trust statement
    contracts are absent.
  - AC: deterministic UUIDs, OSCAL-schema-validated golden output, digest
    tamper, malformed UTF-8 and nested-term properties, scope, time/expiry,
    privacy, totality, and export compatibility tests are green.
  - AC: all repository quality gates pass with coverage at or above 95%.

## Closed Decisions

All architectural decisions are final and research-backed; each lives in
exactly one owning doc with full rationale. This section is the scannable
decision log (an implementer reads it first to avoid re-litigating settled
choices) - the owning docs carry the long-form argument, comparisons, and
sources. Do not reopen a decision without a superseding research note.
D1-D18 were set during the first research round; D9 was revised and D19
added during an adversarial hardening round (both verified against primary
sources, 2026-07-02). D20 supersedes D19 for final MCP `2026-07-28`
compatibility before the unreleased 1.0 publication. D21 adds the separately
versioned external assessment projection without reopening native evidence or
Agent Trust contracts.

| # | Decision and rationale | Owning doc(s) |
|---|------------------------|---------------|
| D1 | **DSSE envelope over a JCS-canonical, in-toto-style Statement** for every signed artifact (attestations, bundles, checkpoints, exports). Signing opaque PAE bytes removes the canonicalization attack surface; the multi-signature array enables witnesses/thresholds; the shape is Sigstore/in-toto/SLSA-proven. JCS pitfalls (int >2^53 -> string, UTF-16 key sort, no unicode normalization) are normative. | `R.02`, `SP.01` |
| D2 | **SPIFFE-ID-shaped actor/issuer strings, carried opaquely**; arbitrary strings accepted; optional offline `did:key`. No first-class DID/VC infrastructure (adoption still early); OAuth 2.1/8707/9728 is host-owned at the MCP layer; WIMSE watch-only. | `R.05`, `SP.10` |
| D3 | **TUF role-subset bundles**: root + delegated signer roles, m-of-n threshold schema (v1 enforces 1), per-role expiry, sequence floors (rollback protection), revocation by list and omission, documented emergency-rotation ceremony. Snapshot/timestamp roles rejected (embedded hosts control update cadence). | `R.03`, `SP.02` |
| D4 | **SCITT is vocabulary alignment plus an optional post-GA adapter, never core.** Registration and non-equivocation auditing require service participation; offline checkpoint, witness, and receipt verification remain useful but do not provide every transparency-service property. No network enters a core decision path. | `R.04`, `R.10` |
| D5 | **Adaptive/ML detection is a core behaviour with a deterministic nil-path**; results are advisory (raise risk, never lower, never sole basis for allow). The ONNX/DeBERTa reference detector ships as an optional post-GA package so core stays zero-ML. | `R.07`, `SP.04` |
| D6 | **No `SigilGuard.Compatibility` namespace.** Legacy modules are deleted; migration lives in `MIGRATING-1.0.md` + `CHANGELOG.md`; historical vectors move to `test/fixtures/historical/`. Justified by near-zero public adoption and the reference consumer's small isolated surface. | `R.07`, `SP.06` |
| D7 | **Eight statement types**: the six original plus `agent_request`/`agent_response` (protocol-neutral names; A2A predicate specifics live in SP.13). Motivated by OWASP ASI07 inter-agent communication. | `SP.01`, `SP.13` |
| D8 | **Sink-aware output contracts in the policy kernel**: `max_size`, `no_raw_credentials`, `digest_only_pii`; transforms `truncate`/`hash`/`mask`; per-sink schema in the policy file. Closes an industry-wide gap (safe output handling). | `SP.04` |
| D9 | **Minimal, well-justified dependencies - NOT zero** (the "zero-dep core" rule was overturned as dogma). Core runtime deps: `:telemetry` + `:nimble_options` (validated schemas + generated docs; safer than hand-rolled validation) + `:jason` (kept; the Jason->stdlib-JSON swap is cancelled). HTTP stays behind the host-provided `SigilGuard.HTTPClient` behaviour for security (no network in decision paths) and host-owns-transport, not dep-avoidance; an optional `req` default client MAY ship. finch leaves core with the registry. JCS encoder stays hand-rolled (no BEAM lib does RFC 8785). Floor `~> 1.18` justified on OTP 27 + set-theoretic types. | `R.07`, `SP.12`, `SP.01` |
| D10 | **Simplified RFC 9162 inclusion + consistency proofs** over the existing Merkle tree (retaining the `sigil-audit-leaf-v1:` domain separation), optional DSSE-multisig **witness cosigning**, per-field **privacy classes** (clear/hashed/redacted/omitted), digest-first **GDPR** stance (erasure targets host payload stores; chain holds only digests). | `R.04`, `SP.05` |
| D11 | **Release path**: align the repo directly to `1.0.0` as the major release line, verify the manual version jump with git_ops and package checks, then hand off publish, tags, pushes, and reference-consumer package validation to the maintainer. | `R.07`, `SP.12` |
| D12 | **Formal threat model** mapping OWASP Agentic Top 10 2026 (ASI01-ASI10) and named MCP attacks to SigilGuard controls with claim level (mitigates/detects/out-of-scope) and a named `TM.01`-`TM.12` test family per claim; host-owned exclusions explicit. | `R.06` |
| D13 | **Policy filenames `SIGILGUARD_POLICY`, `.sigilguard-policy`, `.sigilguard/policy`, `.github/sigilguard-policy`.** Old `SIGIL_POLICY`/`.sigil-policy` names produce a typed `:legacy_policy_filename` startup error naming the new file - no silent fallback. | `SP.04`, `SP.11` |
| D14 | **`SigilGuard.MCP.Gateway` stays a permanent thin facade** over `ToolGateway` (not deprecated), preserving the consumer entry point. | `SP.03`, `SP.08` |
| D15 | **SPDX 2.3 SBOM (existing `mix sigil_guard.sbom`) stays canonical**; SLSA L3 provenance via GitHub artifact attestations; CycloneDX optional later; Rekor anchoring optional. | `SP.05` |
| D16 | **Single OTel attribute namespace `sigilguard.*`** (resolves the v0.2 `sigil.*` vs draft `sigil_guard.*` split; rename is mechanical). | `SP.05` |
| D17 | **Consumer-facing contracts kept byte-identical in v3**: `scan/1` `{:ok,_}|{:hit,[%{name: _}]}`, `scan_and_redact/1`, `policy_verdict/3` `:allowed|:blocked|{:confirm, reason}`, the Identity/Signer/Vault behaviours, `Signer.Ed25519.new/1|sign_with/2|verify/3`, and `%Audit{}` fields. Hit maps extend additively only. Deliberate breaks get 1:1 MIGRATING mappings. | `SP.07` |
| D18 | **Shell-command AST risk analysis is an explicit v1.0 non-goal** (hosts keep their own analyzers); parked in Deferred, revisit post-GA. | `SP.04` |
| D19 | **Superseded by D20.** The pre-release gateway selected `-32050..-32056` before MCP reserved that range. It never ships as the 1.0 contract. | `SP.03`, `SP.08` |
| D20 | **MCP `2026-07-28` alignment without a framework/transport dependency.** SigilGuard uses `-31990..-31984`, canonical structured MCP action binding, required modern result discrimination, manifest v2 display/UI/header coverage, and app-origin/UI-resource verification. Transport sessions, discovery, authorization, subscriptions, tasks, HTTP headers, and rendering remain host-owned. | `R.08`, `SP.16`, `SP.03`, `SP.08` |
| D21 | **OSCAL Assessment Results v1.2.3 is an optional host-context observation projection, never a source of inferred compliance claims.** The adapter binds a pinned native export digest, requires exact reviewed controls and subjects, emits no findings or satisfaction states, and leaves audit export and Agent Trust bytes unchanged. | `R.10`, `SP.17` |

## Deferred (Post-1.0.0)

Parked deliberately; not counted in the Progress Summary. Each item needs
fresh research or a spec update before work starts.

- [ ] Adaptive-detector reference package (Ortex/ONNX classifier such as a
      DeBERTa injection model) as an optional dependency outside core.
- [ ] Shell-command AST risk analysis (D18 non-goal; hosts keep their own
      command analyzers).
- [ ] Trust-mapping DSL beyond SP.10's core actor-pattern default.
- [ ] CI-compiled integration example apps (pinned manual compile
      validation stays the M7 contract until then).
- [ ] Tile-based checkpoint storage for large audit trees.
- [ ] SCITT receipt adapter over the anchor path (D4).
- [ ] Tier-2 integration guides: ex_mcp, Vancouver, mcp_sse, and anubis
      variants beyond the compile check (promotion criteria in SP.14).

## M11 - Security Audit Remediation (SP.18)

- [x] M11.01: Root authority continuity.
- [x] M11.02: Revoked card issuers.
- [x] M11.03: Cold configured modules.
- [x] M11.04: Complete policy boundary facts.
- [x] M11.05: Full replay acceptance lifetime.
- [x] M11.06: Unambiguous signed payloads.
- [x] M11.07: Unbounded streaming candidates.
- [x] M11.08: Overlapping redaction.
- [x] M11.09: Concurrent trust acceptance.
- [x] M11.10: JCS floats and malformed lists.
- [x] M11.11: UTF-8 streaming.
- [x] M11.12: MCP object-key scanning.
- [x] M11.13: Explicit runtime pattern selection.
- [x] M11.14: State and work budgets.
- [x] M11.15: Monotonic replay retention.
- [x] M11.16: Atomic rate limits.
- [x] M11.17: Dependency security and patch updates.
- [x] M11.18: Mutation integrity and security targets.
- [x] M11.19: Shared byte-preserving security utilities.
- [x] M11.20: Documentation drift.
- [x] M11.21: Measured performance regression evidence.
- [x] M11.22: Self-contained Hex package verification.

Validation: 1,634 tests, 22 properties and 36 doctests pass on Elixir 1.18.4 /
OTP 28.5 and Elixir 1.20.2 / OTP 29.0.4; coverage is 95.1%. The canonical gate,
independent JCS campaign, bounded security mutations and unpacked-package
consumer pass. Benchmark results live in `bench/output/audit-remediation.json`;
R.07 records the retained advisory exceptions.
Hosted scheduled runs and reference-consumer deployment remain maintainer-owned.

## M12 - Production Boundary Hardening

- [x] M12.01: Reject ambiguous JSON and canonical audit keys (SP.02, SP.05, SP.09).
- [x] M12.02: Produce structurally valid envelopes (SP.06).
- [x] M12.03: Validate complete audit and witness evidence (SP.05, SP.09).
- [ ] M12.04: Reuse Merkle trees for batch proofs (SP.05).
- [ ] M12.05: Bound trust reads and local anchor writes (SP.02, SP.09).
- [ ] M12.06: Preserve vault state on malformed encryption (SP.10).
- [ ] M12.07: Validate stream configuration explicitly (SP.07).
- [ ] M12.08: Preserve structured adapter values (SP.14).
- [ ] M12.09: Verify full gates and isolated runtime/package/dependency consumers.
