# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## Unreleased Breaking Changes For 1.0.0

SigilGuard 1.0 is a deliberate breaking release. Apply
[`MIGRATING-1.0.md`](MIGRATING-1.0.md) before moving a 0.2.x consumer to the
1.0 line.

- Hardened trust-bundle authority transitions, concurrent rollback floors and
  cumulative revocations. Successors changing delegated authority require the
  new root quorum to countersign; revoked or expired card issuers fail closed.
- Fixed cold security modules, actor/tool policy facts, MCP object-key scanning,
  full replay retention, atomic rate quotas and bounded untrusted work/state.
- Rejected ambiguous null-valued application map fields while preserving v3
  signed bytes. See the [audit acceptance changes](MIGRATING-1.0.md#audit-hardening-of-v3-acceptance).
- Fixed overlapping redaction, unbounded streaming candidates, UTF-8 chunk
  boundaries and JCS float formatting. Added independent float vectors,
  measured scanner improvements and comparable performance regression gates.
- Updated development dependencies including Mint 1.10.0 security fixes and
  Muex 0.9.1. Mutation reports distinguish killed, compiler-invalid and proven
  equivalent mutations; broader bounded security campaigns retain strict scores.
- Added strict deployment guidance and a fresh unpacked-Hex consumer check.

- Removed `SigilGuard.Registry`, `SigilGuard.Registry.Bundle`, and
  `SigilGuard.Registry.Cache`; use
  [`SigilGuard.TrustBundle`](MIGRATING-1.0.md#registry-to-trust-bundles).
- Removed `SigilGuard.Envelope` and verdict-only `_sigil` metadata; use
  [`SigilGuard.Attestation`](MIGRATING-1.0.md#envelope-to-attestation) and
  [`_agent_trust`](MIGRATING-1.0.md#mcp-trust-metadata).
- Removed `SigilGuard.Profile`; use
  [`SigilGuard.TrustProfile`](MIGRATING-1.0.md#profile-to-trustprofile).
- Removed legacy config keys including `:backend`, `:protocol_profile`, and all
  `registry_*` keys; see
  [Configuration Keys](MIGRATING-1.0.md#configuration-keys).
- Renamed policy files from the old SIGIL family to the
  [SIGILGUARD policy filenames](MIGRATING-1.0.md#policy-filenames).
- Renamed confirmation metadata from `_sigil_confirmation` to
  [`_agent_confirmation`](MIGRATING-1.0.md#mcp-confirmation-metadata).
- Aligned the embedded gateway with MCP v2 (`2026-07-28`): structured action
  binding now covers nested keys and non-string values, modern successful
  responses carry `resultType`, and MRTR inputs/state remain bound across
  retries. See [MCP v2](MIGRATING-1.0.md#mcp-v2-2026-07-28).
- Moved gateway denial codes outside JSON-RPC's reserved server-error band to
  the application-defined
  [`-31990..-31984` range](MIGRATING-1.0.md#mcp-json-rpc-rejection-codes);
  the pre-release `-32050..-32056` draft allocation never ships.
- Upgraded capability manifests to
  `sigil_guard_capability_manifest/v2`, binding tool titles, icons, MCP Apps
  UI visibility, and validated `x-mcp-header` annotations.
- Added offline MCP Apps boundaries: same-server app/model visibility checks
  and `SigilGuard.MCP.AppResource` verification for pinned UI bytes, declared
  CSP domains, dedicated app domains, and browser permissions. Verification is
  strictly optioned and bounded to 1 MiB by default; rendering remains
  host-owned.
- Added `SigilGuard.Assessment.OSCAL.project/2`, a pure optional OSCAL
  Assessment Results v1.2.3 observation projection that binds a host-pinned
  canonical audit-export digest, rejects dangling fragment/query-only
  locators, and never infers findings or control satisfaction.
- Removed Finch from the runtime dependency set; HTTP anchor stores use the
  host-provided `SigilGuard.HTTPClient` behaviour.
- Runtime dependencies are intentionally limited to `:telemetry`,
  `:nimble_options`, and `:jason`; integrations, notebooks, and adaptive
  detector examples add no runtime dependency, and `mix deps.audit` is clean
  for the 1.0.0 release line. The test-only Bypass/Cowboy tree currently
  resolves Cowlib 2.19.0, for which Hex reports CVE-2026-43966 and
  CVE-2026-43969, plus CVE-2026-43971 published on 2026-08-18; Cowlib is absent
  from the production dependency tree, all three advisories are explicitly
  acknowledged in the Hex project configuration, affected encoders are not
  called by SigilGuard, and no patched Hex release is available as of
  2026-08-19. The canonical gate runs both `mix deps.audit` and
  `mix hex.audit`. Recheck the exceptions before 2026-09-19 and immediately
  before release, whichever comes first.
- Added a canonical full-history secret scan using a pinned,
  checksum-verified Gitleaks binary. Its ignore file contains only exact
  fingerprints for reviewed synthetic scanner fixtures.
- Malformed hook lists, adaptive-detector modules, and timeout options now fail
  closed at direct policy and runtime-gate entry points instead of allowing an
  invalid `receive ... after` timeout to raise.
- Repo and boundary-policy loaders now validate option containers, keys,
  candidate sets, legacy mappings, and byte limits before filesystem access;
  malformed inputs return `:invalid_options` instead of raising or weakening
  the configured size bound.
- Tagged publication now fails closed unless GitHub reports the exact release
  ref as protected; release documentation distinguishes the environment named
  in workflow YAML from the required owner-managed reviewer, deployment-tag,
  and environment-secret protections.
- Added an unoptimized, 100%-threshold mutation gate for the pure verdict
  ordering primitive; all 78 compilable mutants are killed.
- SPDX generation now binds the declared license from each matching locked Hex
  runtime artifact and fails on missing, malformed, or version-mismatched
  dependency metadata instead of emitting `NOASSERTION`.
- Boundary hook telemetry now covers successful and failed invocations with a
  native-time duration measurement and a normalized `hook_result`, matching the
  observability contract instead of reporting failures only.
- Reconciled the profile, gateway, and boundary specs to the final 1.0 event
  families and made boundary-policy decision telemetry use the shared policy
  shape with a system-time measurement.
- MCP gateway decision telemetry now fires after protocol/result enrichment on
  success and pre-gate denial paths; protocol revision and result type remain
  opt-in high-cardinality OpenTelemetry attributes.
- Revalidated reader-facing research and specification links, replacing moved
  SLSA, NIST, IETF, llm-guard, mcp-use, and historical crate references.
- Expanded `notebooks/` into an eleven-chapter, offline-validated Livebook
  tutorial track with conference/workshop run sheets, a deterministic AI-agent
  attack replay, and an optional ReqLLM proposal path using Livebook secrets;
  the canonical quality gate now executes every shipped Elixir cell offline.
- Changed selected trust-bundle error atoms and config boot errors; see
  [Error Changes](MIGRATING-1.0.md#error-changes).
- Version adoption is explicit: `~> 0.2` remains on the 0.2.x line and
  `~> 1.0` adopts the 1.0 release line; see
  [Version Pinning](MIGRATING-1.0.md#version-pinning).

<!-- changelog -->

## [1.0.0](https://github.com/refpath/sigil_guard/compare/v1.0.0...v1.0.0) (2026-08-24)




### Features:

* guidance: add terse prose skills by futhr

* guidance: align automatic repository skills by Tobias Bohwalli

* notebooks: add conference-ready tutorial track by Tobias Bohwalli

* assessment: add OSCAL evidence projection by Tobias Bohwalli

* mcp: support 2026-07-28 protocol by futhr

* release: gate releases on provenance by futhr

* sbom: verify SBOM digest by futhr

* audit: route anchor storage through HTTPClient by futhr

* audit: bind attestations to evidence by futhr

* audit: add query API by futhr

* audit: add decision CloudEvents projections by futhr

* telemetry: rename telemetry attributes by futhr

* audit: hash private fields by futhr

* audit: embed proofs in exports by futhr

* audit: add witness cosigning by futhr

* audit: build checkpoint state statements by futhr

* audit: add consistency proofs by futhr

* audit: add inclusion proofs by futhr

* scanner: split scanner patterns into bundles by futhr

* decision: separate verdicts from confirmation effects by futhr

* gate: evaluate boundary policy kernel by futhr

* boundary: scope sandbox matrix by futhr

* decision: add unified verdict typed fields by futhr

* identity: add static trust mapping by futhr

* scanner: add scanner match byte limits by futhr

* scanner: emit closed scanner categories by futhr

* boundary: wire repo hook and adaptive sources by futhr

* boundary: add hook and adaptive detector behaviours by futhr

* boundary: add sink aware output contracts by futhr

* repo-policy: add policy facts map by futhr

* boundary: add sandbox identity fields by futhr

* boundary: apply policy rules with precedence by futhr

* boundary: add policy loader legacy guard by futhr

* boundary: add policy file digest fixture by futhr

* boundary: add v3 policy file parser by futhr

* boundary: add unified verdict and policy kernel by futhr

* boundary: add lifecycle taxonomy and boundary input by futhr

* agent-trust: add AgentCard A2A surface by futhr

* gateway: enrich denial metadata by futhr

* gateway: renumber json-rpc errors by futhr

* attestation: strip legacy metadata by futhr

* gateway: issue confirmation tokens by futhr

* confirmation: issue v2 tokens by futhr

* gateway: sign tool attestations by futhr

* gateway: invalidate stale approvals by futhr

* gateway: verify listed manifests by futhr

* gateway: bind result decisions by futhr

* gateway: enforce request guard order by futhr

* gateway: require suspicious parameter confirmation by futhr

* manifest: add capability canonical form by futhr

* trust-bundle: retain revocation union by futhr

* trust-bundle: reject forked rotations by futhr

* trust-bundle: walk root rotations by futhr

* trust-bundle: bootstrap dev bundles by futhr

* trust-bundle: emit telemetry spans by futhr

* trust-bundle: load configured bundle on boot by futhr

* trust-bundle: load local sources by futhr

* trust-bundle: record quarantine failures by futhr

* trust-bundle: cache verified snapshots by futhr

* trust-bundle: verify signed bundles by futhr

* trust-bundle: validate document schema by futhr

* trust-bundle: add public api shell by futhr

* attestation: build statements from decisions by futhr

* attestation: add sign and verify by futhr

* attestation: add digest computation by futhr

* attestation: add metadata helpers by futhr

* attestation: add agent predicate extensions by futhr

* attestation: add trust profile registry by futhr

* attestation: add statement builder by futhr

* attestation: add dsse envelope by futhr

* canonical: add jcs encoder by futhr

* audit: expose signed anchor receipts by futhr

* audit: verify signed anchor receipts by futhr

* audit: require worm anchor receipts by futhr

* audit: add http anchor store by futhr

* audit: trace anchor store operations by futhr

* release: verify generated sbom artifacts by futhr

* audit: add append-only anchor store by futhr

* repo-policy: load repo policy files by futhr

* scanner: validate credential boundaries by futhr

* registry: enforce cache bundle freshness by futhr

* mcp: stream guarded result chunks by futhr

* mcp: release confirmed tool results by futhr

* mcp: compose signed confirmations by futhr

* mcp: accept confirmed tool requests by futhr

* confirmation: support single-use tokens by futhr

* audit: add portable checkpoint exports by futhr

* telemetry: trace signed mcp requests by futhr

* mcp: verify signed tool requests by futhr

* registry: enforce bundle freshness by futhr

* runtime: expand quarantine indicators by futhr

* scanner: harden generic secret validation by futhr

* mcp: return safe json-rpc guard responses by futhr

* audit: add external anchor records by futhr

* repo-policy: add deterministic agent governance by futhr

* audit: add signed checkpoint exports by futhr

* telemetry: add OTel attribute bridge by futhr

* scanner: add staged validation pipeline by futhr

* registry: verify bundle provenance by futhr

* runtime: add action-bound confirmation tokens by futhr

* mcp: add gateway and streaming guard by futhr

* runtime: add boundary-aware gate by futhr

* registry: normalize DID key resolution by futhr

* envelope: add protocol profiles and replay checks by futhr

### Bug Fixes:

* livebooks: use fetched dependencies for offline checks by futhr

* release: enforce protected provenance gates by Tobias Bohwalli

* runtime: fail closed and complete decision telemetry by Tobias Bohwalli

* harden release provenance and verification by Tobias Bohwalli

* release: address validation findings by Tobias Bohwalli

* validation: reject malformed keyword inputs by futhr

* core: fail closed on malformed options by futhr

* audit: harden anchor store boundaries by futhr

* policy: reject symlinked policy files by futhr

* deps: update vulnerable http stack by futhr

* schema: avoid opaque mapset injection from attributes by futhr

* quarantine: support elixir 1.18 compilation by futhr

* bench: avoid stream accumulation overhead by futhr

* patterns: support elixir 1.18 compilation by futhr

* bench: stabilize smoke comparison gate by futhr

* core: harden runtime verification paths by futhr

* attestation: enforce replay expiry semantics by futhr

* registry: require explicit compatibility endpoint by futhr

* audit: validate stored anchors before digest by futhr

* audit: reject invalid export packages by futhr

* audit: reject invalid canonical evidence by futhr

* registry: quarantine invalid bundle terms by futhr

* policy: fail closed on invalid rate options by futhr

* scanner: fail closed on invalid pipeline output by futhr

* scanner: normalize malformed pipeline options by futhr

* telemetry: propagate action digest errors by futhr

* runtime: keep stream holdback on invalid windows by futhr

* runtime: fail closed on invalid confirmation payloads by futhr

* audit: validate local anchor metadata by futhr

* sbom: reject incomplete runtime dependency graphs by futhr

* audit: validate http anchor metadata by futhr

* audit: normalize missing http client errors by futhr

* audit: restrict receipt fetch urls by futhr

* audit: reject conflicting receipt digests by futhr

* sbom: classify tuple dependency options by futhr

* sbom: bind verification to provenance by futhr

* audit: validate fetched anchor records by futhr

* policy: reject malformed risk options by futhr

* audit: reuse checkpoint verification digest by futhr

* signer: validate startup keys by futhr

* registry: validate request timeouts by futhr

* audit: validate http anchor timeouts by futhr

* sbom: validate document identity by futhr

* audit: validate export anchors by futhr

* vault: validate master keys by futhr

* confirmation: validate token options by futhr

* mcp: serialize malformed context errors by futhr

* runtime: normalize context boundaries by futhr

* audit: validate anchor provenance fields by futhr

* audit: validate local receipt uris by futhr

* sbom: verify dependency graph by futhr

* registry: reject malformed identity status by futhr

* audit: reject malformed checkpoints by futhr

* audit: reject remote file receipts by futhr

* audit: reject malformed fetched anchors by futhr

* audit: reject malformed store receipts by futhr

* audit: validate anchors before storage by futhr

* repo-policy: reject malformed matchers by futhr

* telemetry: expose runtime input errors by futhr

* registry: reject masked key material by futhr

* mcp: scan full request payloads by futhr

* runtime: reject malformed context fields by futhr

* patterns: reject malformed metadata by futhr

* audit: validate chain anchors by futhr

* crypto: reject malformed issuer keys by futhr

* runtime: preserve malformed repo context by futhr

* policy: reject malformed repo context by futhr

* audit: reject malformed remote receipts by futhr

* mcp: preserve malformed guard metadata by futhr

* registry: preserve malformed DID fields by futhr

* runtime: preserve malformed changed paths by futhr

* policy: preserve explicit invalid fields by futhr

* validate public key maps by futhr

* registry: harden bundle provenance by futhr

* audit: reject empty receipt signatures by futhr

* audit: reject empty checkpoint fields by futhr

* audit: reject ambiguous anchor receipts by futhr

* patterns: preserve explicit bundle fields by futhr

* preserve explicit string fields by futhr

* audit: harden local anchor lookup by futhr

* audit: enforce signed receipt fetches by futhr

* telemetry: preserve boolean attributes by futhr

* repo-policy: normalize policy edge cases by futhr

* registry: quarantine malformed signed bundles by futhr

* runtime: sanitize blocked decisions by futhr

* audit: reduce chain verification allocation by futhr

### Performance Improvements:

* gateway: avoid duplicate result gating by futhr

* scanner: reuse entropy byte frequencies by futhr

* bench: add reproducible baseline suite by futhr

* scanner: cache built-in patterns by futhr

* runtime: reuse gate scan results in streams by futhr

## [v0.2.0](https://github.com/refpath/sigil_guard/compare/v0.1.1...v0.2.0) (2026-06-10)




### Features:

* registry: retry failed bundle fetches before TTL expiry by futhr

### Bug Fixes:

* backend: reject invalid backend configuration with a clear error by futhr

* registry: reject non-object JSON responses by futhr

* envelope: make verify/2 total over adversarial input by futhr

* audit: enforce HMAC chain contiguity in verify_chain by futhr

* policy: own the default rate table and survive creation races by futhr

* use force-build for NIF compilation in CI by Tobias Bohwalli

## [v0.1.1](https://github.com/refpath/sigil_guard/compare/v0.1.0...v0.1.1) (2026-04-06)




### Bug Fixes:

* add NIF version features and musl/LTO config for precompiled builds by Tobias Bohwalli

## [v0.1.0](https://github.com/refpath/sigil_guard/compare/v0.1.0...v0.1.0) (2026-04-03)




### Features:

* add missing protocol types from sigil-protocol crate by Tobias Bohwalli

* Rust NIF backend via Rustler by Tobias Bohwalli

* SIGIL protocol core library by Tobias Bohwalli

### Bug Fixes:

* remove HTML div wrapper for hex.pm rendering by Tobias Bohwalli

* resolve doc coverage failures in CI by Tobias Bohwalli

* track benchmark output for ExDoc generation by Tobias Bohwalli
