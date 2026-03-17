<div align="center">

# SigilGuard

**SIGIL Protocol integration for Elixir — with optional Rust NIF backend**

[![CI](https://github.com/futhr/sigil_guard/actions/workflows/ci.yml/badge.svg)](https://github.com/futhr/sigil_guard/actions/workflows/ci.yml) [![codecov](https://codecov.io/gh/futhr/sigil_guard/graph/badge.svg?branch=main)](https://codecov.io/gh/futhr/sigil_guard) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)

[Installation](#installation) |
[Quick Start](#quick-start) |
[Documentation](https://github.com/futhr/sigil_guard)

</div>

---

## Overview

SigilGuard provides a high-level Elixir API for the [SIGIL Protocol](https://sigil-protocol.org/),
securing MCP (Model Context Protocol) tool calls and AI agent interactions. Use SigilGuard for:

- **Sensitivity Scanning** — Detect and redact credentials, API keys, PII in text
- **Envelope Signing** — Ed25519 signed `_sigil` metadata for MCP JSON-RPC
- **Policy Enforcement** — Risk-classified trust gating for tool call authorization
- **Tamper-Evident Audit** — HMAC-SHA256 chain integrity for immutable audit logs
- **Registry Client** — Fetch patterns and policies from the SIGIL registry

---

## Features

| Feature | Description | Backend |
|---------|-------------|---------|
| **Sensitivity Scanner** | Regex-based detection of secrets, credentials, PII | Elixir / NIF |
| **Envelope Sign/Verify** | Ed25519 canonical envelope signing | Elixir / NIF |
| **Policy Engine** | Risk classification and trust-level gating | Elixir / NIF |
| **Audit Chain** | HMAC-SHA256 tamper-evident event chain | Elixir / NIF |
| **Secure Vault** | AES-256-GCM encrypted secret storage | Elixir |
| **Registry Client** | REST client with TTL cache | Elixir |
| **Telemetry** | Built-in observability events | Elixir |

---

## Installation

_Note: This project is currently in production evaluation and has not yet been released to Hex. Documentation is available on [GitHub](https://github.com/futhr/sigil_guard)._

### Requirements

- Elixir ~> 1.17
- Erlang/OTP 27+
- Rust toolchain (optional, for NIF backend)

Add `sigil_guard` to your dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:sigil_guard, github: "futhr/sigil_guard"},
    # Optional: For Rust NIF backend
    {:rustler, "~> 0.37", runtime: false, optional: true}
  ]
end
```

### Optional: Rust NIF Backend

For lower-latency operations and protocol parity with the Rust reference implementation:

```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Configure backend
config :sigil_guard, backend: :nif
```

---

## Quick Start

### Sensitivity Scanning

```elixir
# Scan for sensitive content
{:ok, "safe text"} = SigilGuard.scan("safe text")
{:hit, hits} = SigilGuard.scan("AKIAIOSFODNN7EXAMPLE")

# Scan and redact in one pass
"key=[AWS_KEY]" = SigilGuard.scan_and_redact("key=AKIAIOSFODNN7EXAMPLE")
```

Built-in patterns detect: AWS keys, API keys, bearer tokens, database URIs,
private key headers, and generic secrets/passwords.

### Envelope Signing

```elixir
# Sign an envelope
envelope = SigilGuard.Envelope.sign("did:sigil:alice", :allowed,
  signer: MySigner,
  reason: "scan passed"
)

# Verify
:ok = SigilGuard.Envelope.verify(envelope, public_key_b64u)
```

### Policy Enforcement

```elixir
:allowed = SigilGuard.policy_verdict("read_file", :medium)
:blocked = SigilGuard.policy_verdict("delete_database", :low)
{:confirm, reason} = SigilGuard.policy_verdict("create_user", :low)
```

Trust levels: `:low < :medium < :high`
Risk levels: `:low < :medium < :high`

### Tamper-Evident Audit

```elixir
key = :crypto.strong_rand_bytes(32)

events = [
  SigilGuard.Audit.new_event("mcp.tool_call", "alice", "read_file", "success"),
  SigilGuard.Audit.new_event("mcp.tool_call", "bob", "write_file", "success")
]

signed = SigilGuard.Audit.build_chain(events, key)
:ok = SigilGuard.Audit.verify_chain(signed, key)
```

### Secure Vaulting

```elixir
{:ok, _pid} = SigilGuard.Vault.InMemory.start_link([])
{:ok, vault_id} = SigilGuard.Vault.InMemory.encrypt("sk-abc123", "OpenAI key")
{:ok, "sk-abc123"} = SigilGuard.Vault.InMemory.decrypt(vault_id)
```

---

## Configuration

```elixir
config :sigil_guard,
  backend: :elixir, # :elixir | :nif
  registry_url: "https://registry.sigil-protocol.org",
  registry_ttl_ms: :timer.hours(1),
  registry_timeout_ms: 5_000,
  registry_enabled: false,
  scanner_patterns: :built_in
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `backend` | `atom()` | `:elixir` | Backend implementation (`:elixir` or `:nif`) |
| `registry_url` | `String.t()` | `"https://registry.sigil-protocol.org"` | SIGIL registry URL |
| `registry_ttl_ms` | `integer()` | `3_600_000` | Registry cache TTL in ms |
| `registry_timeout_ms` | `integer()` | `5_000` | Registry HTTP timeout in ms |
| `registry_enabled` | `boolean()` | `false` | Enable registry fetching |
| `scanner_patterns` | `atom()` | `:built_in` | Pattern source (`:built_in` or `:registry`) |

### Backend Selection

```elixir
# Check available backends
SigilGuard.Backend.available_backends()
#=> [:elixir] or [:elixir, :nif]

# Get current backend module
SigilGuard.Backend.impl()
#=> SigilGuard.Backend.Elixir
```

---

## Backends

SigilGuard uses a pluggable backend architecture. Protocol operations can run
in pure Elixir or via a Rust NIF for maximum performance.

| Backend | Isolation | Latency | Status | Use Case |
|---------|-----------|---------|--------|----------|
| **Elixir** | Full | Medium | Stable | Default, safe, works everywhere |
| **NIF** | None | Lowest | Beta | Protocol parity, performance |

The NIF backend uses the `sigil-protocol` Rust crate for protocol operations
(envelope signing/verification, canonical bytes) with ed25519-dalek, hmac/sha2,
and regex for extensions (detailed scanning, audit HMAC chain).

---

## Architecture

```
                      SigilGuard (Public API)
                              |
                    SigilGuard.Backend (Behaviour)
                              |
              +---------------+---------------+
              |                               |
              v                               v
SigilGuard.Backend.Elixir         SigilGuard.Backend.NIF
              |                               |
              v                               v
   OTP :crypto + Regex              Rustler + ed25519-dalek + hmac/sha2
```

### Module Overview

```
SigilGuard (Main API)
    |
    +-- SigilGuard.Backend         Backend behaviour and selection
    |   +-- Backend.Elixir         Pure Elixir backend (default)
    |   +-- Backend.NIF            Rust NIF backend (optional)
    |
    +-- SigilGuard.Scanner         Sensitivity scanning engine
    +-- SigilGuard.Patterns        Pattern compilation and management
    +-- SigilGuard.Envelope        SIGIL envelope signing and verification
    +-- SigilGuard.Policy          Risk classification and trust gating
    +-- SigilGuard.Audit           Tamper-evident audit chain
    +-- SigilGuard.Identity        Trust level hierarchy
    +-- SigilGuard.Signer          Cryptographic signing behaviour
    +-- SigilGuard.Vault           Encrypted storage behaviour
    +-- SigilGuard.Registry        SIGIL registry REST client
    +-- SigilGuard.Config          Configuration access
    +-- SigilGuard.Telemetry       Telemetry event definitions
```

---

## Extension Points (Behaviours)

| Behaviour | Purpose | Example Implementation |
|-----------|---------|----------------------|
| `SigilGuard.Signer` | Cryptographic signing | HSM, KMS, cloud key management |
| `SigilGuard.Vault` | Encrypted storage | HashiCorp Vault, AWS KMS, database |
| `SigilGuard.Audit.Logger` | Audit persistence | Database, file, external service |
| `SigilGuard.Identity` | Authentication context | Your auth system integration |
| `SigilGuard.Policy` | Custom risk rules | Domain-specific classification |

---

## Telemetry

SigilGuard emits telemetry events for observability:

| Event | Measurements | Metadata |
|-------|-------------|----------|
| `[:sigil_guard, :scan, :start\|:stop]` | `duration` | `hit_count`, `patterns_checked` |
| `[:sigil_guard, :registry, :fetch, :start\|:stop]` | `duration` | `url`, `count`, `source` |
| `[:sigil_guard, :policy, :decision]` | `system_time` | `action`, `risk_level`, `trust_level` |
| `[:sigil_guard, :audit, :logged]` | `system_time` | `event_type`, `actor` |

---

## Development

```bash
mix setup            # Install dependencies
mix test             # Run tests (unit only)
mix test.nif         # Run with NIF tests
mix lint             # Format + Credo + Dialyzer
mix check            # All quality checks
mix docs             # Generate documentation
mix bench            # Run benchmarks
```

### Running NIF Tests

```bash
# Ensure Rust toolchain is installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

mix test.nif  # Run all tests including NIF
```

---

## Performance

SigilGuard includes benchmarks comparing Elixir and NIF backends:

```bash
mix bench
```

Results are saved to `bench/output/benchmarks.md`.

---

## References

- [SIGIL Protocol](https://sigil-protocol.org/)
- [SIGIL Registry](https://registry.sigil-protocol.org/)
- [Rustler](https://github.com/rusterlium/rustler)

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

SigilGuard is released under the MIT License. See [LICENSE](LICENSE) for details.
