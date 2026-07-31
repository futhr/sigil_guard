# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## Unreleased Breaking Changes For 1.0.0

SigilGuard 1.0 is a deliberate breaking release. Apply
[`MIGRATING-1.0.md`](MIGRATING-1.0.md) before moving a 0.2.x consumer to the
1.0 line.

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
- Removed Finch from the runtime dependency set; HTTP anchor stores use the
  host-provided `SigilGuard.HTTPClient` behaviour.
- Runtime dependencies are intentionally limited to `:telemetry`,
  `:nimble_options`, and `:jason`; integrations, notebooks, and adaptive
  detector examples add no runtime dependency, and `mix deps.audit` is clean
  for the 1.0.0 release line.
- Changed selected trust-bundle error atoms and config boot errors; see
  [Error Changes](MIGRATING-1.0.md#error-changes).
- Version adoption is explicit: `~> 0.2` remains on the 0.2.x line and
  `~> 1.0` adopts the 1.0 release line; see
  [Version Pinning](MIGRATING-1.0.md#version-pinning).

<!-- changelog -->

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
