# SigilGuard V3 Tasks

This is the canonical execution checklist for SigilGuard v3, the embedded
Agent Trust Profile runtime. V3 is a deliberate, spec-governed breaking
release: every architectural decision (D1-D19) is closed, research-backed,
and recorded below with rationale (see Closed Decisions); no open choices
remain. Execute milestones strictly in order F -> M0 -> M1 -> ... -> M8. A
task is done only when its AC bullets hold and its named test families
exist. Migration lives in `MIGRATING-3.0.md`, `CHANGELOG.md`, and release
notes - never in permanent legacy runtime shims.

This file, the research notes (`../research/R.01`-`R.07`), and the specs
(`../specs/SP.01`-`SP.15`) are the complete, self-contained plan of record.
An implementer needs nothing outside `docs/` and the codebase. The decisions
were derived from primary-source research and adversarially verified against
those sources; do not reopen a closed decision without a superseding
research note.

## Orientation (Read First)

Working knowledge for whoever builds this out. Read once, then start at M1.01.

**v0.2.x versus v3.** The current `lib/` is the released 0.2.x runtime; v3 is
a deliberate breaking rewrite, not an incremental patch. The Rust/NIF backend
is already gone and stays gone (`CLAUDE.md` rule 1) - ignore any NIF, rustler,
precompiled-binary, or `SIGIL_GUARD_BUILD` references in history. Do not carry
the v0.2 `Registry`, `Envelope`, `Profile`, `protocol_profile`, or
`registry_*` surfaces into v3; they are deleted in M6 with 1:1 migration
mappings in `MIGRATING-3.0.md`. Legacy golden vectors move to
`test/fixtures/historical/` as migration evidence, not v3 proofs.

**The reference consumer contract.** One production agent runtime embeds
SigilGuard (Elixir `~> 1.19`, OTP 27+), pinned `~> 0.1` today, moving to
`~> 3.0` only after the release-candidate gate. It depends on the stable
contracts in decision **D17**: `scan/1`, `scan_and_redact/1`,
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

**Release mechanics.** `git_ops` manages versioning at release (a `feat`
commit implies a minor bump) but CANNOT derive `3.0.0-rc.1` from 0.2.x
history - the jump to the release candidate is a manual version set (D11, M8),
verified afterward with `mix git_ops.release --dry-run` resuming cleanly.
`~> 3.0` does not resolve a pre-release; consumers pin `"3.0.0-rc.1"` exactly
during the soak. Sequence: `0.2.1` metadata-only -> `3.0.0-rc.1` -> soak plus
a blocking reference-consumer validation -> `3.0.0`.

**Gate and conventions.** Canonical gate `mix check --no-retry` (full list in
`CLAUDE.md`); coverage >= 95%; run `mix credo --strict` before each commit.
Security modules need negative/tamper/replay/expiration/malformed tests
(`CLAUDE.md` rule 9). Conventional commits, no AI attribution or co-author
trailers (rule 10); the maintainer pushes manually.

## Progress Summary

| Milestone | Total | Complete | In Progress | Planned |
|-----------|-------|----------|-------------|---------|
| F - Completed foundation and research | 30 | 30 | 0 | 0 |
| M0 - Decision lock and docs foundation | 22 | 22 | 0 | 0 |
| M1 - Core groundwork | 19 | 19 | 0 | 0 |
| M2 - Embedded trust bundles | 16 | 14 | 0 | 2 |
| M3 - Manifests, gateway, and agent trust | 22 | 0 | 0 | 22 |
| M4 - Boundary scanner and policy kernel | 25 | 0 | 0 | 25 |
| M5 - Audit, telemetry, provenance, threat suite | 26 | 0 | 0 | 26 |
| M6 - Legacy removal, dep cut, migration gate | 31 | 0 | 0 | 31 |
| M7 - Integrations and adoption | 20 | 0 | 0 | 20 |
| M8 - Release | 17 | 0 | 0 | 17 |
| **Total** | **228** | **85** | **0** | **143** |

The table counts every milestone task (F through M8) exactly once. The
Mandatory Gates section is a recurring per-commit checklist and the
Deferred section is post-3.0.0 parking; neither is counted here.

## Operating Rules

- Treat v3 as a breaking refactor.
- Keep the package and project name `SigilGuard`.
- Build around the Agent Trust Profile, not the abandoned upstream protocol.
- Keep old SIGIL-shaped logic only as private implementation ancestry or
  historical fixtures where useful.
- Do not keep a public registry runtime path in v3.
- Do not keep compatibility shims just to preserve v2 APIs.
- Put v2-to-v3 migration in `MIGRATING-3.0.md` and `CHANGELOG.md`.
- Keep SigilGuard embedded/local-first; host applications own transport,
  auth, sandbox execution, storage, and deployment.
- Add tests with every behavior change.
- Keep coverage at or above 95%.
- Execute milestones strictly in order; never start a task whose
  milestone's dependencies are not complete, and never mark a milestone
  complete before its exit criteria hold.
- Any commit that changes, renames, or deletes a consumer-facing contract
  MUST update `test/sigil_guard/conformance/consumer_contracts_test.exs`
  and `MIGRATING-3.0.md` in the same commit.
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
- [ ] `mix deps.audit`.
- [ ] `mix test --cover` with coverage >= 95%.
- [ ] `mix doctor`.
- [ ] `mix dialyzer`.
- [ ] `mix docs`.
- [ ] `mix check --no-retry`.

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
- [x] M0.06 Research note R.07 - ecosystem positioning, dependencies,
      adoption (D5, D6, D9, D11).
  - File: `docs/research/R.07-ecosystem-positioning-dependencies-and-adoption.md`.
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
- [x] M0.15 Create SP.14 - ecosystem integrations and adoption.
  - File: `docs/specs/SP.14-ecosystem-integrations-and-adoption.md`.
- [x] M0.16 Create SP.15 - benchmark methodology and baselines.
  - File: `docs/specs/SP.15-benchmark-methodology-and-baselines.md`.
- [x] M0.17 R.01 surgical edits (deferred items and open questions resolved
      to R.NN pointers) plus `docs/research/README.md` index update.
- [x] M0.18 `docs/README.md` and `docs/specs/README.md` updated with
      SP.13-SP.15 and R.02-R.07 rows, diagrams, ownership rules.
- [x] M0.19 CLAUDE.md reconciliation: rules 3/4 restated for the
      spec-governed v3 break; architecture section updated.
- [x] M0.20 Root README status/roadmap block (0.2.x current, v3.0 planned
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
> Exit criteria: `mix check --no-retry` clean; conformance module (M1.02)
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
    out-of-range) return typed errors that name `MIGRATING-3.0.md` for
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
> Exit criteria: `mix check --no-retry` clean; M1.02 conformance green;
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
  - AC: ETS table `:sigil_guard_trust_bundle` is created by
    `SigilGuard.Application`; `put/1` accepts only sequence strictly above
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
- [ ] M2.09 Negative verification matrix.
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
- [ ] M2.13 Signer-compromise helpers: immediate revocation and emergency
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
> Exit criteria: `mix check --no-retry` clean; M1.02 conformance green;
> facade parity table green; manifest drift matrix green; agent-card
> golden vectors committed.

- [ ] M3.01 `SigilGuard.CapabilityManifest` canonical form.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - CapabilityManifest
    Canonical Form (Digest Field List (Normative)).
  - AC: `new/1` validates the closed field table (required fields, closed
    enums `input_sensitivity`/`output_sensitivity`/`network_access`/
    `reversibility`/`side_effects`, sorted lists, `sandbox` map shape) and
    fails `:invalid_manifest` otherwise; `manifest_format` is
    `sigil_guard_capability_manifest/v1`.
  - Tests: negative, malformed.
- [ ] M3.02 Manifest digest, inner digests, and the `repo_file_write`
      golden fixture.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - CapabilityManifest
    Canonical Form (Canonical Example).
  - AC: `digest/1` computes lowercase-hex SHA-256 over compact JCS preimage
    bytes; `description_sha256` hashes raw UTF-8 bytes;
    `input_schema_sha256`/`output_schema_sha256` hash JCS bytes of the
    schema documents; carried `*_sha256` mismatches fail
    `:invalid_manifest`.
  - AC: `test/fixtures/capability_manifest/repo_file_write` is committed
    and its digest equals the value referenced by the SP.01 `tool_request`
    golden vector (M1.14).
  - Tests: golden vectors, tamper, malformed.
- [ ] M3.03 Suspicious required parameters (schema-injection indicators).
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
- [ ] M3.04 `ToolGateway.guard_request/3` with the normative check order.
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
- [ ] M3.05 `ToolGateway.guard_result/3` with result binding.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - Request And
    Result Attestation Binding (tool_result Binding).
  - AC: `guard_result/3` accepts `:request_action_digest` and binds the
    result to it; quarantine status and scanner summary flow into the
    decision; `guarded_request/3`/`guarded_result/3` and the stream trio
    keep their v2 wire shapes.
  - Tests: negative, tamper, malformed.
- [ ] M3.06 `verify_manifest/2` at `tools/list` time (line-jumping
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
- [ ] M3.07 `tools/list_changed` re-verification and approval invalidation.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - Threat Coverage
    And Host-Owned Exclusions (TM.05, TM.07).
  - AC: a `list_changed` notification forces full re-verification; cached
    approvals die with the manifest because confirmation tokens bind
    `manifest_digest` - a re-listed drifted manifest invalidates every
    outstanding token for that tool.
  - Tests: negative, replay (stale approval after re-list), tamper.
- [ ] M3.08 Manifest drift matrix tests.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - Acceptance
    Criteria.
  - AC: changed name, description, annotations, permissions/scopes, input
    schema, and output schema are each rejected with their named atom
    (`:manifest_digest_mismatch` or `:schema_digest_mismatch`); none falls
    through to a generic error.
  - Tests: tamper (per field), negative.
- [ ] M3.09 `attest_request/3` and `attest_result/3` binding helpers.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - Request And
    Result Attestation Binding; Public API Sketch.
  - AC: `attest_request/3` binds actor, tool/manifest digest, action
    digest, payload digest, context digest, resource, scopes, nonce, and
    expiry via `Attestation.from_decision/3` plus `Attestation.sign/3`;
    `attest_result/3` additionally requires `:request_action_digest`
    (absent fails `:invalid_payload`) and binds result digest, output
    schema digest, sink, quarantine status, and evidence refs.
  - Tests: negative, tamper, malformed.
- [ ] M3.10 Confirmation v2 token format.
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
- [ ] M3.11 `issue_confirmation/5` and the multi-step approval flow.
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
- [ ] M3.12 Transition dual-strip of `_sigil*` alongside `_agent_*`.
  - Spec: `docs/specs/SP.08-mcp-gateway-and-confirmation-contracts.md` -
    Metadata Namespace; `docs/specs/SP.03-mcp-attestation-gateway.md` -
    Implementation Roadmap (M3).
  - AC: during M3-M5 the gateway reads and strips both `_agent_trust`/
    `_agent_confirmation` and legacy `_sigil`/`_sigil_confirmation`
    (mixed-traffic transition); digests are identical whichever namespace
    carries the metadata; `_agent_*` is the only documented public form.
  - AC: the legacy read half is deleted in M6.25 (tracked there).
  - Tests: property (digest equality across namespaces), negative.
- [ ] M3.13 `SigilGuard.MCP.Gateway` rewired as the permanent facade (D14).
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - MCP.Gateway
    Facade (D14).
  - AC: all twenty facade helpers delegate exactly per the spec table
    (confirmation/attestation opt combinations) with identical return
    shapes; parity tests cover every row.
  - Tests: parity suite (facade vs `ToolGateway`), negative.
- [ ] M3.14 JSON-RPC error registry `-32050..-32056` (D19).
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - JSON-RPC Error
    Registry.
  - AC: v3 renumbers gateway rejection codes from v0.2's `-32001..-32003`
    to `-32050` (`blocked`), `-32051` (`confirmation_required`), `-32052`
    (`quarantined`), `-32053` (`manifest_drift` with `drifted_fields`),
    `-32054` (`unknown_manifest`/`manifest_expired`), `-32055`
    (`invalid_attestation` with the SP.01 atom as string), `-32056`
    (`sandbox_required` with isolation fields); each emits exactly the
    documented `data` shape with nil fields omitted; the v0.2 → v3 code
    change is recorded in `MIGRATING-3.0.md`.
  - Tests: negative (per code), golden shape assertions.
- [ ] M3.15 Passthrough, audience, and resource denials.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - Public API Sketch
    (check order step 3); Threat Coverage And Host-Owned Exclusions
    (TM.06, TM.07).
  - AC: `opts[:audience] == opts[:self_resource]` fails
    `:token_passthrough_denied`; `:resource` differing from manifest
    `server` fails `:resource_mismatch`; an audience matching neither the
    manifest `server` nor any `audience` entry fails `:audience_mismatch`;
    each maps to its documented JSON-RPC code.
  - Tests: negative, tamper.
- [ ] M3.16 Sandbox-required denial for privileged tools.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - CapabilityManifest
    Canonical Form (sandbox binding); JSON-RPC Error Registry (-32056).
  - AC: `sandbox.required: true` with a context missing `sandbox_id` or
    below `min_isolation` denies with `:sandbox_required` and emits
    `-32056` with `required_isolation`, `received_isolation`, and
    `sandbox_id_present`.
  - Tests: negative (per isolation level), malformed.
- [ ] M3.17 Poisoned and quarantined tool-result handling tests.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - Threat Coverage
    And Host-Owned Exclusions (TM.02); `-32052` registry row.
  - AC: poisoned/quarantined results produce quarantine decisions with
    sanitized text only (`sanitized_text` in `data` only when
    `include_sanitized: true`); raw output never crosses.
  - Tests: negative, tamper.
- [ ] M3.18 Confirmation-change invalidation matrix.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - Confirmation
    Lifecycle (Digest recomputation).
  - AC: any change since issuance - arguments, sink, actor, `sandbox_id`,
    `isolation_level`, or manifest - fails `:digest_mismatch` or
    `:manifest_digest_mismatch`; tokens are never renewed; a fresh gate
    pass plus re-issue is required.
  - Tests: tamper (one case per changed dimension), negative.
- [ ] M3.19 Transport examples: HTTP MCP, stdio MCP, and in-process tools.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - Integration
    Points; CapabilityManifest Canonical Form (`server` field rule).
  - AC: ExDoc examples cover HTTP MCP (canonical server URI) and
    stdio/in-process tools (host-assigned local runner id); both compile
    as doctests or included example modules.
  - Validation: `mix docs` renders both examples; doctests green.
- [ ] M3.20 `SigilGuard.AgentCard`: canonical form, digest, sign, verify.
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
- [ ] M3.21 `SigilGuard.AgentTrust` helpers with delegation-chain
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
- [ ] M3.22 JWS-to-DSSE card parity and result-pipeline routing.
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
> Exit criteria: `mix check --no-retry` clean; M1.02 conformance green;
> streaming properties green (zero leaked prefixes); all 20 sandbox matrix
> cells tested; canonical policy fixtures committed.

- [ ] M4.01 `SigilGuard.Boundary` normalized policy decision input.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` - Data
    Model (Policy Decision Input (`SigilGuard.Boundary`)).
  - AC: the struct carries source/sink/phase/origin/actor/identity/
    trust_level/trust_zone/tool/resource plus `source_sensitivity` and the
    sandbox fields; validation rejects out-of-enum values with typed
    errors.
  - Tests: negative, malformed.
- [ ] M4.02 Lifecycle phase taxonomy (nine phases).
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Lifecycle Taxonomy.
  - AC: the nine phases (session_start, tool_request,
    permission_requested, permission_resolved, tool_result, file_changed,
    model_ingress, model_egress, session_end) are a closed set shared by
    Boundary, Hooks, and policy `phase:` matchers.
  - Tests: negative (unknown phase), malformed.
- [ ] M4.03 `BoundaryPolicy.evaluate/2` with decision combination.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Decision Combination (Normative).
  - AC: deterministic evaluation over Boundary inputs; combination follows
    the normative rules; absent `default` line means `confirm`.
  - Tests: negative, property (determinism: equal inputs, equal outputs).
- [ ] M4.04 Policy-file parser: version line, sections, folding.
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
- [ ] M4.05 Policy-file digest and canonical fixtures.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` - Policy
    File Digest; Canonical Example And Fixture Convention.
  - AC: `policy_file_digest` is SHA-256 over the raw bytes exactly as read
    (no normalization); the exact canonical example bytes are committed as
    `test/fixtures/boundary_policy/canonical.policy` with
    `canonical.expected.json` reproducing rules, contracts, repo section,
    and digest byte-deterministically.
  - Tests: golden vectors, negative.
- [ ] M4.06 D13 policy filenames and the legacy-filename typed error.
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
- [ ] M4.07 Precedence and matched-rule explanations.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Precedence.
  - AC: `block > quarantine > confirm > redact > allow` across matching
    rules; `[repo]` keeps its implemented
    `block > require_approval > allow` order and unmatched-path defaults;
    decisions carry matched-rule ids and explanations.
  - Tests: negative, property (precedence total order).
- [ ] M4.08 Runtime gate rewire onto `BoundaryPolicy` with the unified
      verdict enum.
  - Spec: `docs/specs/SP.07-runtime-gate-and-streaming-contracts.md` - V3
    Rewire; V3 Decision Contract (Unified Verdict Enum; New Typed Fields).
  - AC: the gate evaluates through `BoundaryPolicy`; the unified verdict
    enum (allow/block/confirm/redact/quarantine) replaces the v2 dual
    vocabulary per the spec's mapping table; `%Decision{}` gains typed
    `matched_rules` and `evidence_refs`; source, sink, trust zone, actor,
    resource, and phase appear on runtime decisions.
  - AC: D17 facade contracts stay byte-stable - M1.02 stays green.
  - Tests: negative, property (old-to-new verdict mapping), conformance.
- [ ] M4.09 Sandbox identity fields on `SigilGuard.Context`.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Sandbox Identity (Isolation Levels).
  - AC: `sandbox_id` and `isolation_level`
    (`:none | :container | :vm | :remote_attested`, nil allowed) plus
    `workspace_root_digest` and network posture fields exist;
    `Context.validate/1` rejects out-of-enum values with
    `:invalid_isolation_level`; omitted level is byte-distinct from
    `"none"` in the context digest.
  - Tests: negative, malformed.
- [ ] M4.10 Side-effect mismatch matrix with the fail-closed quarantine
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
- [ ] M4.11 Sandbox matrix cell tests (all 20 cells).
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Side-Effect Mismatch Matrix; Acceptance Criteria.
  - AC: every class x level cell is asserted, including missing-sandbox
    and mismatch cases for risky tools, and the `isolation:absent`
    override path.
  - Tests: negative (20 cells), expiration not applicable, malformed
    (invalid level input).
- [ ] M4.12 Sink-aware output contracts (`[contracts]` section).
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
- [ ] M4.13 Contract transforms and evaluation order.
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
- [ ] M4.14 Lethal-trifecta example policy with doctest.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Dataflow Rules And Lethal Trifecta; Complete Policy File Example.
  - AC: the canonical example's first three rules encode the trifecta
    (`sensitivity:private` x untrusted origin/zone x
    `sink:external,network`): `trust:low,medium` blocks, `trust:high`
    routes to confirm whose token binds the action digest including
    `sandbox_id`; a doctest executes the policy against representative
    inputs.
  - Tests: doctest, negative (all three conjunct drop-outs), property.
- [ ] M4.15 Repo policy facts in boundary decisions.
  - Spec: `docs/specs/SP.11-repo-policy-kernel-contracts.md` - Policy Facts
    For Boundary Decisions.
  - AC: the policy-facts map feeds `BoundaryPolicy` exactly per the SP.11
    shape; repo verdict facts appear in decision explanations.
  - Tests: negative, malformed.
- [ ] M4.16 `SigilGuard.Hooks` behaviour.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` - Hooks
    Behaviour (Result Semantics).
  - AC: nine optional callbacks map 1:1 to phases as `on_<phase>`;
    `on_session_start/2` and `on_session_end/2` are notification-only, the
    other seven blockable; hooks contribute `{:block, _}`/`{:confirm, _}`
    and advisory signals (risk may raise, never lower; indicators join
    with source `:hook`, rule id `hook.<module>.<phase>`); hooks cannot
    emit allow/redact/quarantine.
  - Tests: negative (per callback), malformed (`:invalid_hook_result`).
- [ ] M4.17 Hooks dispatcher: timeout and fail-closed matrix.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Timeouts And Fail-Closed Matrix.
  - AC: every invocation is bounded by `:hook_timeout_ms` (default
    `5_000`); on blockable phases timeout/crash/invalid-result each yield
    verdict `block` with reasons `:hook_timeout`/`:hook_crash`/
    `:invalid_hook_result`; on notification-only phases the same failures
    log-and-continue via telemetry; `{:block, _}` short-circuits remaining
    hooks.
  - Tests: negative (all six matrix cells), tamper (crashing hook).
- [ ] M4.18 Adaptive detector behaviour with the deterministic nil path.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Adaptive Detector Behaviour (D5).
  - AC: `SigilGuard.AdaptiveDetector.analyze/3` returns advisory
    indicators (source `:adaptive`) that raise risk but never lower it and
    never produce an allow; detector errors, timeouts, crashes, or
    malformed indicator maps degrade to zero indicators recorded as
    `adaptive_error`; with `:adaptive_detector` unset, decisions are
    byte-identical to a build without the behaviour (proven by test).
  - Tests: negative, malformed, property (nil-path byte equality).
- [ ] M4.19 Scanner validators and confidence thresholds.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Scanner Hit Extension And Pattern-Set Split.
  - AC: staged-pipeline validators and confidence scoring are expanded;
    scores land in the additive `confidence` hit field in `0.0..1.0`.
  - Tests: negative, property (score bounds).
- [ ] M4.20 Pattern-set split with bundle-suppliable sets and pluggable
      quarantine indicators.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Pattern Sets.
  - AC: secret, injection, and poisoning sets are distinct; bundle pattern
    entries gain a `set` field and each set can be supplied or overridden
    independently (SP.02 wiring); quarantine consumes the injection and
    poisoning sets with the current seven indicators as built-in defaults.
  - Tests: negative, malformed (bad `set` values), tamper.
- [ ] M4.21 Hit-map additive extension (D17-safe).
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` - Hit
    Map (D17, Additive Only).
  - AC: `scan/1` and `scan_and_redact/1` return shapes are unchanged;
    required keys narrow to `name`/`match`/`offset`/`length`; the built-in
    pipeline always emits `replacement_hint`, `category`
    (`:secret | :injection | :poisoning`), `confidence`, `severity`, and
    `span` (must equal `{offset, length}`); M1.02 conformance stays green.
  - Tests: conformance, negative, property (`span` equality).
- [ ] M4.22 `max_match_bytes` and the holdback-window invariant.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Holdback Invariant (Normative).
  - AC: built-in values (aws_access_key 20, private_key 40, 256 for the
    rest) are declared; bundle patterns may declare `1..4096` (default
    256); `Runtime.Stream.new/2` raises the effective window to the
    largest active `max_match_bytes` when the configured window is
    smaller.
  - Tests: negative, property (window >= max pattern bound).
- [ ] M4.23 Streaming property tests: every byte-offset split.
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
- [ ] M4.24 Curated split-secret vector file.
  - Spec: `docs/specs/SP.04-boundary-scanner-and-policy-kernel.md` -
    Curated Vector File.
  - AC: `test/fixtures/streaming/split_secret_vectors.json` is committed
    with the required vector classes per built-in pattern (first-byte,
    one-before-match-end, mid-match splits; mid-codepoint; grapheme
    cluster; all-1-byte full secret) plus Unicode-confusable negatives
    that MUST NOT match or redact; each vector asserts
    `expected_hit_names` and exact `expected_emitted`.
  - Tests: golden vectors, negative (confusables).
- [ ] M4.25 Config-driven trust mapping (core default).
  - Spec: `docs/specs/SP.10-vault-and-identity-contracts.md` -
    Config-Driven Trust Mapping.
  - AC: the small core default ships: an actor-pattern to trust_level map
    with the documented `@spec`; unmatched actors take the documented
    default; the mapping DSL beyond this default stays deferred.
  - Tests: negative, malformed (bad patterns), property (total mapping).

## M5 - Audit, Telemetry, Provenance, And Threat Suite

> Specs: `SP.05`, `SP.09`, `R.06`. Depends on: M1-M4.
> Exit criteria: `mix check --no-retry` clean; M1.02 conformance green;
> all twelve TM families green; proofs verify unmodified 0.2.x checkpoint
> roots.
> Rule for TM tasks (move-don't-duplicate): scenarios already implemented
> in earlier milestones are MOVED into their TM module or referenced by
> exact test name - never copy-pasted; every TM module's `@moduledoc`
> cites its R.06 Control Mapping row numbers and claim level.

- [ ] M5.01 Inclusion proofs: generation and verification.
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
- [ ] M5.02 Consistency proofs and the 1..256 equivalence property.
  - Spec: `docs/specs/SP.05-audit-and-release-provenance.md` - Inclusion
    And Consistency Proofs (Consistency Proof Verification; Golden Vector:
    Five-Event Tree).
  - AC: 3-to-5, 4-to-5, and 5-to-5 consistency vectors verify and
    regenerate byte-identically; a property proves promotion/RFC 9162 root
    equality for sizes 1..256; truncation and fork attempts fail
    `:inconsistent_tree`.
  - Tests: golden vectors, property, tamper, negative.
- [ ] M5.03 DSSE checkpoint statements.
  - Spec: `docs/specs/SP.05-audit-and-release-provenance.md` - Witness
    Cosigning (checkpoint statement);
    `docs/specs/SP.09-audit-chain-and-anchor-contracts.md` - Normative
    Constants.
  - AC: `Checkpoint.to_statement/1` builds the
    `https://sigilguard.dev/audit-checkpoint-state/v1` DSSE payload over
    exactly `(merkle_root, tree_size, generated_at)`; existing checkpoint
    records are unchanged.
  - Tests: golden vectors, negative, malformed.
- [ ] M5.04 Witness cosigning and threshold verification.
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
- [ ] M5.05 Signed audit event exports and export-package DSSE form.
  - Spec: `docs/specs/SP.05-audit-and-release-provenance.md` - Data Model
    (Signed Audit Event; Event Hash Field List (Exact, Ordered); Export
    Package DSSE Form).
  - AC: signed events match the canonical example and the exact ordered
    event-hash field list; export packages gain optional
    `checkpoint_statement` and proof fields in DSSE form;
    `%SigilGuard.Audit{}` and `sign_event/3` are unchanged (D17).
  - Tests: golden vectors, tamper, negative, plus truncation detection
    (dropped/reordered events in exports are detected).
- [ ] M5.06 Privacy classification enforcement.
  - Spec: `docs/specs/SP.05-audit-and-release-provenance.md` - Privacy
    Classification (Normative) (GDPR Stance (Digest-First)).
  - AC: the per-field class table (clear/hashed/redacted/omitted) is
    enforced over every signed event field; hashed fields use the `fh1:`
    form via `hash_field/2`; a missing field-hash key yields
    `"redacted-v1"`; raw secrets never appear in chain events; key
    destruction (crypto-erasure) leaves all verification green.
  - Tests: negative, property (no plaintext survives), tamper.
- [ ] M5.07 OTel attribute rename to `sigilguard.*` with cardinality
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
- [ ] M5.08 CloudEvents projection.
  - Spec: `docs/specs/SP.05-audit-and-release-provenance.md` - CloudEvents
    Projection.
  - AC: projection emits `specversion` `1.0`, type
    `io.sigilguard.decision.v1`, and privacy-filtered `data` only.
  - Tests: golden shape, negative (privacy filter).
- [ ] M5.09 Audit read and query API (pure reads).
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
- [ ] M5.10 Bind attestations to audit evidence refs.
  - Spec: `docs/specs/SP.05-audit-and-release-provenance.md` - Data Model;
    `docs/specs/SP.01-sigilguard-trust-profile.md` - Data Model (evidence).
  - AC: attestation predicates carry evidence refs
    (`kind: checkpoint/export/anchor`) resolving to audit artifacts;
    round-trip from decision to attestation to audit event is asserted.
  - Tests: negative, tamper (dangling refs detected).
- [ ] M5.11 `SigilGuard.HTTPClient` behaviour and anchor-store conversion.
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
- [ ] M5.12 WORM anchor adapter and release SBOM verification docs.
  - Spec: `docs/specs/SP.05-audit-and-release-provenance.md` - Release
    Provenance (D15); Security Considerations.
  - AC: host-owned WORM/append-only anchor adapter guidance and SBOM
    verification steps are ExDoc-rendered; SBOM digest drift at
    verification fails with `:sbom_digest_mismatch`.
  - Validation: `mix docs` renders; commands in the docs execute as
    written.
- [ ] M5.13 Release provenance workflow (SLSA L3).
  - Spec: `docs/specs/SP.05-audit-and-release-provenance.md` - Release
    Provenance (D15).
  - AC: the tagged-release workflow runs `attest-build-provenance`
    (permissions `id-token: write`, `attestations: write`) with subjects =
    Hex tarball + SBOM; `gh attestation verify` gates publish; the release
    additionally signs an SP.01 `release` statement whose `artifacts` list
    includes tarball and SBOM `{name, sha256}` entries; a CI example shows
    consumer-side verification.
  - Tests: workflow dry-run on a test tag; negative (verify failure blocks
    publish).
- [ ] M5.14 Rename the legacy scanner interception audit event.
  - Spec: `docs/specs/SP.09-audit-chain-and-anchor-contracts.md` - V3
    Extensions (Owned By SP.05).
  - AC: the old interception event name is replaced by a neutral security
    event; chain verification over historical events with the old name
    still verifies (names are data, not structure).
  - Tests: negative, golden vectors (historical chain).
- [ ] M5.15 TM.01 threat family - prompt injection via tool results.
  - Spec: `docs/research/R.06-agentic-threat-model-and-control-mapping.md`
    - Control Mapping row 1; Test Families; `SP.04`.
  - AC: `test/sigil_guard/threat_model/tm01_injection_via_tool_results_test.exs`
    proves result-phase scanning, streaming holdback, and sink contracts
    handle the attack fixtures at the documented claim level (mitigates).
  - Tests: negative, tamper, malformed.
- [ ] M5.16 TM.02 threat family - tool poisoning via descriptions/metadata.
  - Spec: `R.06` - Control Mapping row 2; `SP.03` (manifest digest
    pinning).
  - AC: `.../tm02_tool_poisoning_test.exs` proves description/annotation/
    schema drift denies via manifest digest pinning (mitigates).
  - Tests: negative, tamper.
- [ ] M5.17 TM.03 threat family - line jumping.
  - Spec: `R.06` - Control Mapping row 3; `SP.03` (verify-before-list).
  - AC: `.../tm03_line_jumping_test.exs` proves `tools/list` content is
    verified before any definition reaches model context and before any
    invocation (mitigates).
  - Tests: negative, tamper.
- [ ] M5.18 TM.04 threat family - schema injection.
  - Spec: `R.06` - Control Mapping row 4; `SP.03` (Suspicious Required
    Parameters).
  - AC: `.../tm04_schema_injection_test.exs` proves adversarial required
    params (for example credential-shaped names) are disclosed, digest
    bound, recomputed, and force confirm (mitigates + detects).
  - Tests: negative, tamper, malformed.
- [ ] M5.19 TM.05 threat family - rug pull / TOFU drift.
  - Spec: `R.06` - Control Mapping rows 5 and 18; `SP.03` (list_changed).
  - AC: `.../tm05_rug_pull_test.exs` proves drift rejection and that
    `tools/list_changed` drops cached approvals and forces re-verification,
    covering the config-swap analog (mitigates).
  - Tests: negative, tamper, replay.
- [ ] M5.20 TM.06 threat family - confused deputy and consent replay.
  - Spec: `R.06` - Control Mapping rows 6 and 21; `SP.01`, `SP.03`.
  - AC: `.../tm06_confused_deputy_test.exs` proves audience/resource/actor
    binding plus nonce replay scope and token single-use defeat replayed
    or forged approvals (mitigates, partial).
  - Tests: negative, replay, expiration, tamper.
- [ ] M5.21 TM.07 threat family - token passthrough and session hijacking.
  - Spec: `R.06` - Control Mapping rows 7 and 8; `SP.03`, `SP.05`.
  - AC: `.../tm07_passthrough_session_test.exs` proves the explicit
    passthrough deny (`:token_passthrough_denied`) and the session-hijack
    assists (per-action nonce, `list_changed` re-verification, audit
    session boundary) at their claim levels (mitigates; detects partial).
  - Tests: negative, replay, tamper.
- [ ] M5.22 TM.08 threat family - memory and context poisoning.
  - Spec: `R.06` - Control Mapping row 9; `SP.04` (model-ingress gating).
  - AC: `.../tm08_memory_poisoning_test.exs` proves retrieved memory/
    context crosses the scanner and trust-zone policy at model ingress
    with digest provenance (mitigates + detects).
  - Tests: negative, tamper, malformed.
- [ ] M5.23 TM.09 threat family - lethal-trifecta dataflow.
  - Spec: `R.06` - Control Mapping rows 10 and 11; `SP.04` (Dataflow Rules
    And Lethal Trifecta).
  - AC: `.../tm09_lethal_trifecta_test.exs` proves the conjunction rule
    blocks/confirms per trust level and that untrusted-origin content
    never enters exec/command sinks (mitigates; execution runtime
    out-of-scope).
  - Tests: negative, property (conjunct coverage), tamper.
- [ ] M5.24 TM.10 threat family - A2A impersonation and delegation abuse.
  - Spec: `R.06` - Control Mapping rows 12, 13, and 20; `SP.13`.
  - AC: `.../tm10_a2a_abuse_test.exs` proves card verification against
    bundle issuers, unknown-agent quarantine, and the delegation-chain
    tamper/depth rules (mitigates; detects-at-boundary for rogue agents).
  - Tests: negative, tamper, replay, expiration.
- [ ] M5.25 TM.11 threat family - supply chain.
  - Spec: `R.06` - Control Mapping rows 14-17; `SP.02` (verification,
    quarantine).
  - AC: `.../tm11_supply_chain_test.exs` proves tampered/revoked/replayed
    bundle and manifest drift detection with quarantine evidence, and
    documents the out-of-scope tooling-RCE rows as assume-compromised
    posture (detects, partial; out-of-scope rows cited).
  - Tests: negative, tamper, replay.
- [ ] M5.26 TM.12 threat family - repudiation, audit tamper, truncation.
  - Spec: `R.06` - Control Mapping rows 19 and 22; `SP.05`.
  - AC: `.../tm12_repudiation_test.exs` proves chain tamper and truncation
    are detectable via HMAC chain, checkpoints, inclusion/consistency
    proofs, and anchors, and that per-hop attestation evidence
    reconstructs propagation paths (mitigates + detects; evidence-only for
    cascades).
  - Tests: tamper, negative, property (truncation detection).

## M6 - Legacy Removal, Dependency Cut, And Migration Gate

> Specs: `SP.12`, `SP.06`, `SP.01` (V3 Configuration Surface).
> Depends on: M1-M5.
> Exit criteria (tier-2 consolidated gate): `mix check --no-retry` clean;
> M1.02 conformance green; the M6.24 completeness script proves every
> deleted surface has a 1:1 `MIGRATING-3.0.md` row; runtime dependency set
> is exactly the intended minimal set (`:telemetry`, `:nimble_options`,
> `:jason`); the reference-consumer upgrade branch (M6.29)
> builds and passes its full suite plus its security-conformance
> acceptance tests, with all findings folded back (M6.30).

- [ ] M6.01 Delete `SigilGuard.Registry`.
  - Spec: `docs/specs/SP.12-legacy-remote-bundle-adapter-contracts.md` -
    V3 Removal Map.
  - AC: the module is deleted (not hidden); `fetch_bundle/1`,
    `resolve_did/2`, `resolve_key/2`, `fetch_policies/1` map to their
    MIGRATING rows; old registry tests move to migration/removal tests.
  - Tests: removal test (module absent; calls raise cleanly), conformance.
- [ ] M6.02 Delete `SigilGuard.Registry.Bundle`.
  - Spec: `SP.12` - V3 Removal Map.
  - AC: deleted; provenance checks live in `TrustBundle` verification;
    legacy golden vectors preserved under `test/fixtures/historical/`.
  - Tests: removal test, golden vectors (historical still parse as
    fixtures).
- [ ] M6.03 Delete `SigilGuard.Registry.Cache`.
  - Spec: `SP.12` - V3 Removal Map.
  - AC: deleted; `TrustBundle.Cache` is the only cache; no ETS table or
    supervision child remains for the registry path.
  - Tests: removal test, negative (boot has no registry children).
- [ ] M6.04 Delete `SigilGuard.Profile`.
  - Spec: `docs/specs/SP.01-sigilguard-trust-profile.md` - Public Modules
    Removed In V3.
  - AC: deleted; `SigilGuard.TrustProfile` is the replacement; all doc
    references updated.
  - Tests: removal test, conformance.
- [ ] M6.05 Delete `SigilGuard.Envelope`.
  - Spec: `docs/specs/SP.06-envelope-and-native-backend-contracts.md` - V3
    Transition Rules; `SP.01` - Migration: Envelope To Attestation.
  - AC: deleted; the Envelope-to-Attestation field mapping table is
    reproduced 1:1 in `MIGRATING-3.0.md` (M6.18); the known-consumers note
    (two call sites: tool-args metadata attach and socket auth) has exact
    v3 replacement calls documented.
  - Tests: removal test, conformance.
- [ ] M6.06 Move legacy envelope/profile vectors to
      `test/fixtures/historical/`.
  - Spec: `SP.06` - Known Consumers; V3 Transition Rules (fixture path).
  - AC: old golden vectors live under `test/fixtures/historical/` and are
    exercised only by migration/removal tests; the old-vocabulary scan
    exempts that path.
  - Tests: golden vectors (historical), negative (nothing under `lib/`
    reads them).
- [ ] M6.07 Remove public examples centered on verdict-only envelopes.
  - Spec: `SP.01` - Public API Surface; `SP.06` - V3 Transition Rules.
  - AC: no README/ExDoc example signs or verifies a verdict-only envelope;
    replacements use `SigilGuard.Attestation` statements.
  - Validation: docs vocabulary scan clean; `mix docs` renders.
- [ ] M6.08 `SigilGuard.Config` strict closed-key validation.
  - Spec: `SP.01` - V3 Configuration Surface.
  - AC: `SigilGuard.Config.validate!/0` runs at `Application.start/2` and
    fails closed with `SigilGuard.ConfigError`: reason
    `:legacy_contract_removed` for removed keys, `:unknown_config_key`
    for unrecognized keys; every message names the offending key and
    `MIGRATING-3.0.md`; kept keys (`:trust_bundle`, `:scanner_patterns`,
    `:http_client`, `:attestation_ttl_ms`, `:max_skew_ms`,
    `:replay_ttl_ms`, `:vault_master_key`) validate per their table rows.
  - Tests: negative (per kept-key validation rule), malformed.
- [ ] M6.09 Removed-key error matrix.
  - Spec: `SP.01` - Removed Keys; `SP.12` - V3 Removal Map.
  - AC: `:backend`, `:protocol_profile`, all nine `registry_*` keys, and
    the `scanner_patterns: :registry` value each raise
    `SigilGuard.ConfigError` at boot naming the key and
    `MIGRATING-3.0.md`.
  - Tests: negative (one boot test per removed key/value).
- [ ] M6.10 D13 policy filename rename verification.
  - Spec: `docs/specs/SP.11-repo-policy-kernel-contracts.md` - V3 Policy
    Filenames (D13); `SP.04` - Policy Filenames.
  - AC: with M4.06 shipped, every legacy filename
    (old SIGIL-name variants) produces
    `{:error, {:legacy_policy_filename, found, use}}` and no silent
    fallback path exists anywhere; `MIGRATING-3.0.md` carries the four
    positional rename rows.
  - Tests: negative (all four legacy names), conformance.
- [ ] M6.11 Remove finch and the `SigilGuard.Finch` pool.
  - Spec: `SP.12` - Dependency Removal (D9); `SP.05` -
    SigilGuard.HTTPClient Behaviour (D9).
  - AC: `{:finch, _}` leaves `mix.exs`; the pool leaves the application
    supervision tree; zero finch references remain in the runtime tree;
    the anchor store runs solely on `SigilGuard.HTTPClient` (M5.11); a
    reference finch adapter remains documentation only.
  - Tests: negative (boot without finch), no-network sweep stays green.
- [ ] M6.12 Runtime dependency-set assertion test.
  - Spec: `SP.12` - Dependency Removal (D9).
  - AC: a permanent test fails whenever the runtime dependency set differs
    from the intended minimal set (`:telemetry`, `:nimble_options`,
    `:jason`) plus OTP/stdlib applications; dev and test deps are exempt;
    adding a runtime dep requires updating this test and a D9-style record.
  - Tests: the assertion itself plus a negative fixture proving it trips.
- [ ] M6.13 `MIGRATING-3.0.md` skeleton with the dependency update example.
  - Spec: `SP.12` - V3 Removal Map; `SP.01` - Migration: Envelope To
    Attestation.
  - AC: the guide exists with section structure covering every mapping
    below; includes the `{:sigil_guard, "~> 0.2"}` to
    `{:sigil_guard, "~> 3.0"}` example.
  - Validation: M6.24 completeness script; link check.
- [ ] M6.14 MIGRATING: `_sigil` to `_agent_trust` before/after examples.
  - Spec: `docs/specs/SP.08-mcp-gateway-and-confirmation-contracts.md` -
    Metadata Namespace.
  - AC: literal before/after payload examples; the mixed-traffic
    transition note lives only here.
  - Validation: completeness script; vocabulary scan exemption honored.
- [ ] M6.15 MIGRATING: `_sigil_confirmation` to `_agent_confirmation`
      before/after examples.
  - Spec: `SP.08` - Metadata Namespace.
  - AC: literal before/after examples including the `:confirmation_token`
    option path.
  - Validation: completeness script.
- [ ] M6.16 MIGRATING: `Registry.fetch_bundle/1` to `TrustBundle.load/1`.
  - Spec: `SP.12` - V3 Removal Map.
  - AC: code-level mapping with source construction
    (`{:file, _}`/`{:priv, _, _}`/`{:binary, _}`) guidance.
  - Validation: completeness script.
- [ ] M6.17 MIGRATING: `Registry.resolve_key/2` and `resolve_did/2` to
      trust-bundle issuer lookup.
  - Spec: `SP.12` - V3 Removal Map.
  - AC: issuer lookup via verified bundle roles; host-auth pointer for DID
    flows.
  - Validation: completeness script.
- [ ] M6.18 MIGRATING: `Envelope.sign/verify` to `Attestation.sign/verify`
      mapping table.
  - Spec: `SP.01` - Migration: Envelope To Attestation.
  - AC: the field mapping table is reproduced 1:1; both known consumer
    call-site shapes get exact replacement snippets.
  - Validation: completeness script.
- [ ] M6.19 MIGRATING: `Profile` to `TrustProfile`.
  - Spec: `SP.01` - Public Modules Removed In V3.
  - AC: function-level mapping; profile id constant migration noted.
  - Validation: completeness script.
- [ ] M6.20 MIGRATING: config migration table.
  - Spec: `SP.01` - V3 Configuration Surface (Removed Keys).
  - AC: every removed key row with its replacement (or "none") matching
    the SP.01 table verbatim.
  - Validation: completeness script.
- [ ] M6.21 MIGRATING: expected error-change table.
  - Spec: `SP.01` - Error Handling; `SP.02` - Error Handling (reconciled
    atoms).
  - AC: old-to-new atom rows (`:rollback_detected` to
    `:sequence_below_floor`, `:expired_bundle` to `:bundle_expired`,
    `:unknown_issuer` to `:unknown_key_id`, `:invalid_schema`/
    `:invalid_bundle` to `:invalid_bundle_format`, `:missing_signature`/
    `:unsigned_bundle` to `:invalid_envelope`) plus the new
    `SigilGuard.ConfigError` boot behavior.
  - Validation: completeness script.
- [ ] M6.22 MIGRATING: pin note for v2 users.
  - Spec: `SP.12` - Release Sequence (D11).
  - AC: states that `~> 0.2` users never auto-upgrade to v3 and that
    `~> 3.0` does not match release candidates (exact rc pin required).
  - Validation: completeness script.
- [ ] M6.23 CHANGELOG breaking-change section.
  - Spec: `SP.12` - Release Sequence (D11).
  - AC: a breaking-change section enumerates removals with MIGRATING
    anchors; git_ops conventions untouched (generated entries are not
    hand-edited elsewhere).
  - Validation: link check; completeness script.
- [ ] M6.24 Migration completeness-gate script.
  - Spec: `SP.12` - Acceptance Criteria.
  - AC: a repo script cross-references the M6 deletion diff (removed
    modules, functions, config keys, filenames) against `MIGRATING-3.0.md`
    and fails on any unmapped removal; it also link-checks the migration
    doc; wired into CI for the M6 branch onward.
  - Tests: fixture-driven script test (unmapped removal fails; mapped
    passes).
- [ ] M6.25 Remove legacy `_sigil*` reading; strip rule reduces to the six
      SP.01 keys.
  - Spec: `docs/specs/SP.03-mcp-attestation-gateway.md` - Implementation
    Roadmap (M6); `SP.01` - Metadata Strip Rule.
  - AC: the gateway no longer reads `_sigil`/`_sigil_confirmation`; the
    digest strip set is exactly SP.01's six keys; mixed-traffic behavior
    is documented only in `MIGRATING-3.0.md`.
  - Tests: negative (legacy metadata is inert), property (digest
    stability), conformance.
- [ ] M6.26 README rewrite: installation, examples, configuration.
  - Spec: `SP.01` - V3 Configuration Surface; `SP.14` - Announcement Kit
    And Listings (tagline).
  - AC: installation snippet says `{:sigil_guard, "~> 3.0"}`; MCP examples
    are replaced with Agent Trust attestation examples; the configuration
    table lists exactly the SP.01 kept keys.
  - Validation: docs vocabulary scan; `mix docs`; README snippets compile
    as doctests where applicable.
- [ ] M6.27 README rewrite: profile section and legacy-language cleanup.
  - Spec: `SP.01` - V3 Position; `SP.12` - V3 Removal Map.
  - AC: the protocol-profile section becomes an Agent Trust Profile
    section; Rust/NIF backend references are gone; the historical upstream
    link remains only as historical context; registry cache prose is
    replaced by trust-bundle cache docs.
  - Validation: vocabulary scan; forbidden-terms scan; link check.
- [ ] M6.28 Package metadata cleanup: hosted-registry language removed.
  - Spec: `SP.12` - V3 Removal Map; `SP.14` - Announcement Kit And
    Listings.
  - AC: `mix.exs` package description/links carry no hosted-registry or
    NIF language; metadata matches the v3 positioning.
  - Validation: `mix hex.build` dry inspection; vocabulary scan.
- [ ] M6.29 Reference-consumer upgrade-branch validation (tier-2 gate).
  - Spec: `SP.12` - Release Sequence (D11); `SP.07` - Stability
    Guarantees (D17).
  - AC: an upgrade branch of the reference consumer builds against this
    repo as a path dependency applying ONLY `MIGRATING-3.0.md` steps; the
    observed diff matches the expected shape: exactly two `_sigil` call
    sites change (tool-args metadata attach and socket auth) plus dropped
    registry/NIF config keys; its three sigil-prefixed boot keys are
    untouched.
  - AC: its full test suite and its security-conformance acceptance tests
    (identity spoofing, repudiation, communications poisoning) pass.
  - Validation: gate record in the M6 notes; any uncovered step spawns an
    M6.30 item.
- [ ] M6.30 Fold reference-consumer findings back into MIGRATING.
  - Spec: `SP.12` - Acceptance Criteria.
  - AC: every migration step discovered during M6.29 that was missing from
    `MIGRATING-3.0.md` is added; the M6.24 script and M6.29 build are
    re-run green afterward.
  - Validation: completeness script green on the updated doc.
- [ ] M6.31 CLAUDE.md final flip and docs/README v3 diagrams.
  - Spec: this file - Closed Decisions; `SP.01` - Public API Surface.
  - AC: CLAUDE.md rule 3 names the `_agent_trust`/`_agent_confirmation`
    contracts as the compatibility surface; the architecture section drops
    Registry-era wording; `docs/README.md` diagrams show the v3 module
    topology.
  - Validation: docs lint (M0.22) green; vocabulary scan clean.

## M7 - Integrations And Adoption

> Specs: `SP.14`, `SP.15`. Depends on: M6.
> Exit criteria: `mix check --no-retry` clean; M1.02 conformance green;
> all five livebooks execute offline; `bench/output/benchmarks.md`
> published with the environment block; OpenSSF passing badge earned;
> announcement drafts exist and remain unpublished.

- [ ] M7.01 ExDoc cheatsheet.
  - Spec: `docs/specs/SP.14-ecosystem-integrations-and-adoption.md` -
    ExDoc Artifacts.
  - AC: `guides/cheatsheet.cheatmd` covers gate verdicts, the policy
    grammar, attestation sign/verify calls, and the confirmation flow.
  - Validation: `mix docs` renders without warnings.
- [ ] M7.02 Threat-model guide rendered from R.06.
  - Spec: `SP.14` - ExDoc Artifacts; `R.06` - Control Mapping.
  - AC: `guides/threat-model.md` reproduces the control-mapping table,
    claim-level definitions, and host-owned exclusions in substance; no
    claim exceeds its R.06 claim level.
  - Validation: `mix docs`; claim-level cross-check against R.06.
- [ ] M7.03 hermes_mcp integration guide.
  - Spec: `SP.14` - Tier 1: hermes_mcp; Per-Target Acceptance.
  - AC: interceptor and middleware/plug placements both shown; the
    anubis_mcp compile variant passes; denials map onto the SP.03 JSON-RPC
    error registry; pinned-version compile validation recorded.
  - Validation: guide example compiles warnings-as-errors at its pin.
- [ ] M7.04 Jido integration guide.
  - Spec: `SP.14` - Tier 1: Jido; Per-Target Acceptance.
  - AC: denial surfaces as a Jido action error without raising; `actor` is
    populated from the agent identity; pinned compile validation recorded.
  - Validation: guide example compiles at its pin.
- [ ] M7.05 LangChain/ReqLLM integration guide.
  - Spec: `SP.14` - Tier 1: LangChain Elixir And ReqLLM.
  - AC: request and result sides both gated; the ReqLLM pipeline-step
    variant appears in the same guide; pinned compile validation recorded.
  - Validation: guide example compiles at its pin.
- [ ] M7.06 Tidewave gating guide with shipped example policy.
  - Spec: `SP.14` - Tier 1: Tidewave; Per-Target Acceptance.
  - AC: the shipped policy blocks eval-class tools, requires approval for
    repo writes, allows schema/doc reads; the guide states Tidewave is
    dev-only and the guard is defense in depth; `examples/tidewave/`
    carries the policy file.
  - Validation: guide example compiles at its pin; policy fixture parses.
- [ ] M7.07 Livebook: quick start.
  - Spec: `SP.14` - Livebooks.
  - AC: `notebooks/quick-start.livemd` covers install, first scan, gate
    verdicts, and redaction with a Run in Livebook badge.
  - Validation: executes top-to-bottom offline via local-path
    `Mix.install` (M7.12).
- [ ] M7.08 Livebook: policy and lethal trifecta.
  - Spec: `SP.14` - Livebooks; `SP.04` - Dataflow Rules And Lethal
    Trifecta.
  - AC: `notebooks/policy-and-lethal-trifecta.livemd` executes the R.06
    row-10 trifecta rule against live policy evaluation.
  - Validation: offline execution (M7.12).
- [ ] M7.09 Livebook: audit export and proofs.
  - Spec: `SP.14` - Livebooks; `SP.05` - Inclusion And Consistency Proofs.
  - AC: `notebooks/audit-export-and-proofs.livemd` walks chain,
    checkpoint, inclusion proof, and signed-export verification.
  - Validation: offline execution (M7.12).
- [ ] M7.10 Livebook: hermes integration stub.
  - Spec: `SP.14` - Livebooks (hermes stub rule).
  - AC: `notebooks/hermes-integration.livemd` exercises the interceptor
    contract against an in-notebook stub shaped like the pinned interface;
    it MUST NOT fetch `hermes_mcp` (real wiring lives in M7.03).
  - Validation: offline execution (M7.12).
- [ ] M7.11 Livebook: threat scenarios.
  - Spec: `SP.14` - Livebooks; `R.06` - Test Families.
  - AC: `notebooks/threat-scenarios.livemd` demonstrates selected TM
    families (tool poisoning, rug pull, schema injection) end to end.
  - Validation: offline execution (M7.12).
- [ ] M7.12 Livebook offline validation script.
  - Spec: `SP.14` - Livebooks (validation rule).
  - AC: a script runs every notebook's code cells via `Mix.install` on the
    local repository path in a network-denied environment and fails on any
    error; wired into CI or the release checklist.
  - Tests: script test (a failing cell fails the run; clean run passes).
- [ ] M7.13 Benchmark corpus and harness matrix (BM.01-BM.08).
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
- [ ] M7.14 `bench/compare.exs` regression gate and committed baseline.
  - Spec: `SP.15` - CI Regression Thresholds.
  - AC: `bench/baseline.json` is committed with its environment block;
    `compare.exs` fails on >20% median regression or a missing baseline
    scenario, passes new scenarios, and is binding only on a matching
    runner class; the baseline refresh procedure is documented in-repo.
  - Tests: fixture test (25% regression fails; 15% passes; missing
    scenario fails); JSON shape test against the data model.
- [ ] M7.15 Post-rewire full benchmark run published.
  - Spec: `SP.15` - Scenario Matrix; Environment Disclosure Format.
  - AC: the full matrix runs after the v3 gateway/scanner rewiring and the
    results land in `bench/output/benchmarks.md` with the environment
    block; numbers are labeled "measured", never "guaranteed".
  - Validation: published file carries all eight scenarios and the block.
- [ ] M7.16 llm-guard scanner-scope comparison.
  - Spec: `SP.15` - Cross-Ecosystem Comparison Rules.
  - AC: comparison covers `SigilGuard.scan/1` versus llm-guard input
    scanners only, same machine/corpus/run, versions and configuration
    disclosed, deterministic and ML paths labeled, corpus published for
    reproduction.
  - Validation: comparison artifact satisfies every fairness rule.
- [ ] M7.17 SECURITY.md.
  - Spec: `SP.14` - SECURITY.md.
  - AC: states supported versions (latest 3.x; final 0.2.x gets security
    fixes for six months after GA), private-vulnerability-report channel,
    the 72 h / 7 d / 90 d response SLO, and the pointer to SP.02's
    emergency rotation ceremony as the signer-compromise runbook.
  - Validation: link check; policy renders on the repo security tab.
- [ ] M7.18 OpenSSF Best Practices badge to passing.
  - Spec: `SP.14` - OpenSSF Best Practices Badge.
  - AC: the bestpractices.dev entry reaches passing, mapping existing
    gates onto the criteria; the badge MUST be earned before any
    announcement fires.
  - Validation: badge status recorded; README badge added.
- [ ] M7.19 Announcement kit drafts, listings text, and Hex metadata
      review.
  - Spec: `SP.14` - Announcement Kit And Listings.
  - AC: `docs/announcements/elixir-forum.md`, `elixir-radar.md`, and
    `thinking-elixir.md` drafts exist with the recorded tagline; the
    awesome-elixir PR text and hex.pm keyword/metadata review are
    prepared; publishing is gated on 3.0.0 GA and MUST never fire against
    an rc; claims stay within R.06 levels.
  - Validation: drafts exist unpublished; claim-level cross-check.
- [ ] M7.20 ElixirConf CFP draft (date-gated).
  - Spec: `SP.14` - Announcement Kit And Listings.
  - AC: `docs/announcements/elixirconf-cfp.md` exists; submission is
    additionally gated on the CFP window and on 3.0.0 GA.
  - Validation: draft exists; gating noted inside the draft.

## M8 - Release

> Specs: `SP.12` (Release Sequence (D11)), `SP.15` (SLO Ratification),
> `SP.05` (Release Provenance). Depends on: M6 (M7 required before GA).
> Exit criteria (tier-3 gate): `mix check --no-retry` clean; M1.02
> conformance green; the reference consumer validates green against the
> PUBLISHED 3.0.0-rc.1 pinned exactly (blocking for GA); 3.0.0 published
> with provenance and SBOM; announcements fired only after GA.

- [ ] M8.01 Publish 0.2.1 metadata-only from `release/0.2`.
  - Spec: `SP.12` - Release Sequence (D11) step 1.
  - AC: branch `release/0.2` is cut at tag `v0.2.0`; 0.2.1 carries only
    corrected Hex metadata and a README status banner; the package diff
    against 0.2.0 contains zero `lib/` changes (go/no-go).
  - Validation: recorded package diff; Hex release visible.
- [ ] M8.02 git_ops major-bump dry-run verification.
  - Spec: `SP.12` - Release Sequence (D11) step 2.
  - AC: a dry run demonstrates git_ops cannot derive 0.2.x to 3.0.0-rc.1
    from commit history; the documented manual-jump procedure is the
    recorded consequence.
  - Validation: dry-run output archived in the release notes draft.
- [ ] M8.03 Manual version jump to 3.0.0-rc.1.
  - Spec: `SP.12` - Release Sequence (D11) step 2.
  - AC: `mix.exs` version and the CHANGELOG entry are set manually; tag
    `v3.0.0-rc.1` is created.
  - Validation: tag exists; version and changelog agree.
- [ ] M8.04 Post-tag git_ops resume check (rc line).
  - Spec: `SP.12` - Release Sequence (D11) step 2 go/no-go.
  - AC: `mix git_ops.release --dry-run` resumes cleanly from the new
    version line after the manual jump.
  - Validation: dry-run output archived.
- [ ] M8.05 Publish 3.0.0-rc.1 with the exact-pin note.
  - Spec: `SP.12` - Release Sequence (D11) step 2.
  - AC: rc.1 is published; the rc announcement states that `~> 3.0` does
    NOT match prerelease versions and consumers MUST pin `"3.0.0-rc.1"`
    exactly.
  - Validation: Hex release visible; note present in the rc notes.
- [ ] M8.06 Reference-consumer rc validation (blocking tier-3 gate).
  - Spec: `SP.12` - Release Sequence (D11) step 3; Acceptance Criteria.
  - AC: the reference consumer validates green against the PUBLISHED
    3.0.0-rc.1 pinned exactly (not a path dep): full suite plus its
    security-conformance acceptance tests; this gate blocks GA.
  - Validation: gate record; failures reopen M6.30 fold-back before any
    further rc.
- [ ] M8.07 SLSA L3 provenance and SBOM on the release workflow.
  - Spec: `docs/specs/SP.05-audit-and-release-provenance.md` - Release
    Provenance (D15).
  - AC: the rc and GA tags produce SLSA v1 provenance via
    `attest-build-provenance` with tarball + SBOM subjects; `gh
    attestation verify` gates publish; the SP.01 `release` statement signs
    tarball and SBOM digests.
  - Tests: workflow run on rc tag; negative (verification failure blocks).
- [ ] M8.08 Socket-denying no-network sweep.
  - Spec: `SP.02` - Loading Sources (No-network guarantee); `SP.05` -
    SigilGuard.HTTPClient Behaviour (trust model).
  - AC: a suite-wide sweep proves every scan/gate/policy/attestation/
    bundle/audit decision path opens no sockets (anchor HTTP puts are the
    sole, explicitly host-triggered exception); runs in CI on the release
    branch.
  - Tests: negative (port-list and socket-deny assertions across paths).
- [ ] M8.09 Fuzz final pass over attestations, bundles, manifests, and
      policy files.
  - Spec: `SP.01`/`SP.02`/`SP.03`/`SP.04` - Error Handling tables.
  - AC: randomized malformed-input campaigns against every public decode/
    verify entry point produce only taxonomy atoms - no raises, no
    timeouts; corpus seeds are committed for reproduction.
  - Tests: malformed (fuzz harness), negative.
- [ ] M8.10 Telemetry conformance tests for every event family.
  - Spec: `SP.02`/`SP.03`/`SP.04`/`SP.05` - Telemetry And Observability
    tables.
  - AC: every documented event family fires with exactly the documented
    measurement/metadata keys; no undocumented events are emitted; the
    `sigilguard.*` namespace holds everywhere.
  - Tests: telemetry conformance suite (one assertion block per family).
- [ ] M8.11 SLO ratification from rc.1 measurements.
  - Spec: `docs/specs/SP.15-benchmark-methodology-and-baselines.md` - SLO
    Ratification.
  - AC: the full matrix runs on the disclosed reference environment at
    rc.1; SLOs are ratified as measured median and p99 plus 50% headroom
    into SP.15's Success Metrics (bump `updated:`); until then no
    "guaranteed" language anywhere.
  - Validation: SP.15 update commit; published figures cite the ratified
    numbers only.
- [ ] M8.12 Soak window (14 days).
  - Spec: `SP.12` - Release Sequence (D11) step 3.
  - AC: a fixed 14-day soak runs with rc.1 in the reference consumer's
    staging environment; regressions reopen the rc cycle (rc.2) rather
    than shortening the window.
  - Validation: soak log with start/end dates and zero unresolved
    regressions.
- [ ] M8.13 Release checklist execution.
  - Spec: `SP.12` - Release Sequence (D11); `SP.05` - Release Provenance.
  - AC: the checklist covering docs, SBOM, provenance, benchmarks, and Hex
    metadata is executed and archived for the GA release.
  - Validation: checklist archived with the GA tag.
- [ ] M8.14 Dependency-audit posture note.
  - Spec: `SP.12` - Dependency Removal (D9); `R.07`.
  - AC: release notes record the audited posture: runtime deps are the
    intended minimal set (`:telemetry`, `:nimble_options`, `:jason`) chosen
    on merit; integrations and adaptive detectors add no runtime deps
    (docs/optional packages only); `mix deps.audit` clean at tag.
  - Validation: note present; M6.12 assertion green at tag.
- [ ] M8.15 Publish 3.0.0 GA with the git_ops resume check.
  - Spec: `SP.12` - Release Sequence (D11) step 4.
  - AC: GA is published; a post-publish `mix git_ops.release --dry-run`
    confirms normal operation from the 3.0.0 line.
  - Validation: Hex release visible; dry-run output archived.
- [ ] M8.16 Fire announcements and listings (GA only).
  - Spec: `SP.14` - Announcement Kit And Listings.
  - AC: forum/radar/podcast announcements publish from the M7.19 drafts;
    the awesome-elixir PR and Hex keyword updates land; nothing fires
    against an rc; claims stay within R.06 levels.
  - Validation: published links recorded; claim-level cross-check.
- [ ] M8.17 Reference-consumer production bump to `~> 3.0`.
  - Spec: `SP.12` - Release Sequence (D11) step 4.
  - AC: the reference consumer moves from the exact rc pin to `~> 3.0` in
    production; its suite stays green on GA.
  - Validation: gate record closing the v3 program.

## Closed Decisions

All architectural decisions are final and research-backed; each lives in
exactly one owning doc with full rationale. This section is the scannable
decision log (an implementer reads it first to avoid re-litigating settled
choices) - the owning docs carry the long-form argument, comparisons, and
sources. Do not reopen a decision without a superseding research note.
D1-D18 were set during the first research round; D9 was revised and D19
added during an adversarial hardening round (both verified against primary
sources, 2026-07-02).

| # | Decision and rationale | Owning doc(s) |
|---|------------------------|---------------|
| D1 | **DSSE envelope over a JCS-canonical, in-toto-style Statement** for every signed artifact (attestations, bundles, checkpoints, exports). Signing opaque PAE bytes removes the canonicalization attack surface; the multi-signature array enables witnesses/thresholds; the shape is Sigstore/in-toto/SLSA-proven. JCS pitfalls (int >2^53 -> string, UTF-16 key sort, no unicode normalization) are normative. | `R.02`, `SP.01` |
| D2 | **SPIFFE-ID-shaped actor/issuer strings, carried opaquely**; arbitrary strings accepted; optional offline `did:key`. No first-class DID/VC infrastructure (adoption still early); OAuth 2.1/8707/9728 is host-owned at the MCP layer; WIMSE watch-only. | `R.05`, `SP.10` |
| D3 | **TUF role-subset bundles**: root + delegated signer roles, m-of-n threshold schema (v1 enforces 1), per-role expiry, sequence floors (rollback protection), revocation by list and omission, documented emergency-rotation ceremony. Snapshot/timestamp roles rejected (embedded hosts control update cadence). | `R.03`, `SP.02` |
| D4 | **SCITT is vocabulary alignment plus an optional post-GA adapter, never core.** A networked transparency service would break the offline guarantee; checkpoint + witness cosigning gives equivalent properties offline. | `R.04` |
| D5 | **Adaptive/ML detection is a core behaviour with a deterministic nil-path**; results are advisory (raise risk, never lower, never sole basis for allow). The ONNX/DeBERTa reference detector ships as an optional post-GA package so core stays zero-ML. | `R.07`, `SP.04` |
| D6 | **No `SigilGuard.Compatibility` namespace.** Legacy modules are deleted; migration lives in `MIGRATING-3.0.md` + `CHANGELOG.md`; historical vectors move to `test/fixtures/historical/`. Justified by near-zero public adoption and the reference consumer's small isolated surface. | `R.07`, `SP.06` |
| D7 | **Eight statement types**: the six original plus `agent_request`/`agent_response` (protocol-neutral names; A2A predicate specifics live in SP.13). Motivated by OWASP ASI07 inter-agent communication. | `SP.01`, `SP.13` |
| D8 | **Sink-aware output contracts in the policy kernel**: `max_size`, `no_raw_credentials`, `digest_only_pii`; transforms `truncate`/`hash`/`mask`; per-sink schema in the policy file. Closes an industry-wide gap (safe output handling). | `SP.04` |
| D9 | **Minimal, well-justified dependencies - NOT zero** (the "zero-dep core" rule was overturned as dogma). Core runtime deps: `:telemetry` + `:nimble_options` (validated schemas + generated docs; safer than hand-rolled validation) + `:jason` (kept; the Jason->stdlib-JSON swap is cancelled). HTTP stays behind the host-provided `SigilGuard.HTTPClient` behaviour for security (no network in decision paths) and host-owns-transport, not dep-avoidance; an optional `req` default client MAY ship. finch leaves core with the registry. JCS encoder stays hand-rolled (no BEAM lib does RFC 8785). Floor `~> 1.18` justified on OTP 27 + set-theoretic types. | `R.07`, `SP.12`, `SP.01` |
| D10 | **Simplified RFC 9162 inclusion + consistency proofs** over the existing Merkle tree (retaining the `sigil-audit-leaf-v1:` domain separation), optional DSSE-multisig **witness cosigning**, per-field **privacy classes** (clear/hashed/redacted/omitted), digest-first **GDPR** stance (erasure targets host payload stores; chain holds only digests). | `R.04`, `SP.05` |
| D11 | **Release path**: publish `0.2.1` metadata-only (zero `lib/` diff, from a `release/0.2` branch at tag v0.2.0) -> manual jump to `3.0.0-rc.1` (git_ops cannot derive it; `~> 3.0` does not match a pre-release, pin exact) -> soak + blocking reference-consumer rc gate -> `3.0.0`. | `R.07`, `SP.12` |
| D12 | **Formal threat model** mapping OWASP Agentic Top 10 2026 (ASI01-ASI10) and named MCP attacks to SigilGuard controls with claim level (mitigates/detects/out-of-scope) and a named `TM.01`-`TM.12` test family per claim; host-owned exclusions explicit. | `R.06` |
| D13 | **Policy filenames `SIGILGUARD_POLICY`, `.sigilguard-policy`, `.sigilguard/policy`, `.github/sigilguard-policy`.** Old `SIGIL_POLICY`/`.sigil-policy` names produce a typed `:legacy_policy_filename` startup error naming the new file - no silent fallback. | `SP.04`, `SP.11` |
| D14 | **`SigilGuard.MCP.Gateway` stays a permanent thin facade** over `ToolGateway` (not deprecated), preserving the consumer entry point. | `SP.03`, `SP.08` |
| D15 | **SPDX 2.3 SBOM (existing `mix sigil_guard.sbom`) stays canonical**; SLSA L3 provenance via GitHub attest-build-provenance; CycloneDX optional later; Rekor anchoring optional. | `SP.05` |
| D16 | **Single OTel attribute namespace `sigilguard.*`** (resolves the v0.2 `sigil.*` vs draft `sigil_guard.*` split; rename is mechanical). | `SP.05` |
| D17 | **Consumer-facing contracts kept byte-identical in v3**: `scan/1` `{:ok,_}|{:hit,[%{name: _}]}`, `scan_and_redact/1`, `policy_verdict/3` `:allowed|:blocked|{:confirm, reason}`, the Identity/Signer/Vault behaviours, `Signer.Ed25519.new/1|sign_with/2|verify/3`, and `%Audit{}` fields. Hit maps extend additively only. Deliberate breaks get 1:1 MIGRATING mappings. | `SP.07` |
| D18 | **Shell-command AST risk analysis is an explicit v3.0 non-goal** (hosts keep their own analyzers); parked in Deferred, revisit post-GA. | `SP.04` |
| D19 | **Gateway JSON-RPC rejection codes renumbered to `-32050..-32056`** (blocked/confirmation_required/quarantined/manifest_drift/unknown_manifest/invalid_attestation/sandbox_required). Legal but ambiguous at v0.2's `-32001..-32003` (a client can conflate `-32001` with an SDK transport timeout; MCP's `-32042` shows the low band filling); the v3 break moves to a clean sub-range with buffer. | `SP.03`, `SP.08` |

## Deferred (Post-3.0.0)

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
