# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Pluggable backend architecture** with two processing backends:
  - `SigilGuard.Backend.Elixir` - Default, pure Elixir using OTP `:crypto` (safe, works everywhere)
  - `SigilGuard.Backend.NIF` - Rust NIF wrapping `sigil-protocol` crate (protocol parity)
- `SigilGuard.Backend` behaviour defining unified interface for all backends
- Rust NIF scaffolding via Rustler (`native/sigil_guard_nif/`)
- Backend comparison benchmarks (`bench/run.exs`)
- Comprehensive CI pipeline (GitHub Actions)
- Cross-backend parity tests ensuring identical outputs
- Project tooling alignment: excoveralls, ex_check, doctor, sobelow, mix_audit, benchee

### Changed

- `SigilGuard` facade now dispatches to `SigilGuard.Backend.impl()` for backend selection
- Configuration now supports `backend: :elixir | :nif` option
- Version bump to 0.2.0

## [0.1.0] - 2026-03-01

### Added

- Initial release
- Sensitivity scanning with 6 built-in patterns (AWS keys, API keys, bearer tokens, database URIs, private keys, generic secrets)
- SIGIL envelope signing and verification (Ed25519)
- Policy enforcement with risk classification and trust gating
- Tamper-evident audit logging with HMAC-SHA256 chain integrity
- Secure vaulting with AES-256-GCM encryption
- SIGIL registry REST client with TTL cache
- Comprehensive documentation and typespecs
- Telemetry events for observability

[Unreleased]: https://github.com/futhr/sigil_guard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/futhr/sigil_guard/releases/tag/v0.1.0
