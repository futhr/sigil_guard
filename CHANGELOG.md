# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](Https://conventionalcommits.org) for commit guidelines.

<!-- changelog -->

## [v0.2.0](https://github.com/futhr/sigil_guard/compare/v0.1.1...v0.2.0) (2026-06-10)




### Features:

* registry: retry failed bundle fetches before TTL expiry by futhr

### Bug Fixes:

* backend: reject invalid backend configuration with a clear error by futhr

* registry: reject non-object JSON responses by futhr

* envelope: make verify/2 total over adversarial input by futhr

* audit: enforce HMAC chain contiguity in verify_chain by futhr

* policy: own the default rate table and survive creation races by futhr

* use force-build for NIF compilation in CI by Tobias Bohwalli

## [v0.1.1](https://github.com/futhr/sigil_guard/compare/v0.1.0...v0.1.1) (2026-04-06)




### Bug Fixes:

* add NIF version features and musl/LTO config for precompiled builds by Tobias Bohwalli

## [v0.1.0](https://github.com/futhr/sigil_guard/compare/v0.1.0...v0.1.0) (2026-04-03)




### Features:

* add missing protocol types from sigil-protocol crate by Tobias Bohwalli

* Rust NIF backend via Rustler by Tobias Bohwalli

* SIGIL protocol core library by Tobias Bohwalli

### Bug Fixes:

* remove HTML div wrapper for hex.pm rendering by Tobias Bohwalli

* resolve doc coverage failures in CI by Tobias Bohwalli

* track benchmark output for ExDoc generation by Tobias Bohwalli
