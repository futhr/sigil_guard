# AGENTS.md

Guidance for AI agents working with SigilGuard.

## Project Overview

SigilGuard is an Elixir library providing SIGIL Protocol integration for MCP security. It features a pluggable backend architecture with pure Elixir and Rust NIF backends.

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
   OTP :crypto + Regex              Rustler + sigil-protocol
```

### Backend Comparison

| Backend | Isolation | Latency | Status | Use Case |
|---------|-----------|---------|--------|----------|
| **Elixir** | Full | Medium | Stable | Default, safe, works everywhere |
| **NIF** | None | Lowest | Beta | Protocol parity, performance |

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
    |   +-- Audit.Logger           Audit logger behaviour
    +-- SigilGuard.Identity        Trust level hierarchy
    +-- SigilGuard.Signer          Cryptographic signing behaviour
    |   +-- Signer.Ed25519         Ed25519 signer implementation
    +-- SigilGuard.Vault           Vault behaviour and utilities
    |   +-- Vault.InMemory         ETS-based in-memory vault
    +-- SigilGuard.Registry        SIGIL registry REST client
    |   +-- Registry.Cache         TTL cache for registry data
    +-- SigilGuard.Config          Configuration access
    +-- SigilGuard.Telemetry       Telemetry event definitions
```

## Key Files

| File | Purpose |
|------|---------|
| `lib/sigil_guard.ex` | Main API module, dispatches to backend |
| `lib/sigil_guard/backend.ex` | Backend behaviour definition and selection |
| `lib/sigil_guard/backend/elixir.ex` | Pure Elixir backend implementation |
| `lib/sigil_guard/backend/nif.ex` | NIF backend (Rustler) |
| `lib/sigil_guard/scanner.ex` | Regex-based sensitivity scanning |
| `lib/sigil_guard/envelope.ex` | SIGIL envelope sign/verify |
| `lib/sigil_guard/policy.ex` | Risk classification and trust gating |
| `lib/sigil_guard/audit.ex` | HMAC-SHA256 chain integrity |
| `lib/sigil_guard/identity.ex` | Trust level hierarchy |
| `lib/sigil_guard/vault.ex` | Encrypted storage behaviour |
| `lib/sigil_guard/registry.ex` | SIGIL registry REST client |
| `lib/sigil_guard/config.ex` | Configuration access |
| `lib/sigil_guard/telemetry.ex` | Telemetry events and helpers |
| `native/sigil_guard_nif/` | Rust NIF source code |

## Development Commands

```bash
mix setup                       # Install deps
mix test                        # Run tests (unit only)
mix test --include nif          # Run with NIF tests
mix lint                        # Format + Credo + Dialyzer
mix check                       # All quality checks
mix sobelow                     # Security analysis
mix docs                        # Generate docs
mix coveralls                   # Test coverage report
mix bench                       # Run benchmarks
```

## Testing

- **Unit tests** - Run without Rust, test pure Elixir logic
- **NIF tests** - Tagged `@moduletag :nif`, require Rust toolchain
- **Parity tests** - Verify Elixir and NIF backends produce identical output

Test structure:
```
test/
+-- sigil_guard/
|   +-- scanner_test.exs       # Scanning tests
|   +-- envelope_test.exs      # Envelope sign/verify tests
|   +-- policy_test.exs        # Policy evaluation tests
|   +-- audit_test.exs         # Audit chain tests
|   +-- backend_test.exs       # Backend dispatch tests
|   +-- backend/
|       +-- elixir_test.exs    # Elixir backend tests
|       +-- nif_test.exs       # NIF backend tests
|       +-- parity_test.exs    # Cross-backend parity tests
+-- support/
    +-- test_signer.ex         # Deterministic test signer
    +-- nif_case.ex            # NIF test case template
```

## Telemetry Events

| Event | Measurements | Metadata |
|-------|--------------|----------|
| `[:sigil_guard, :scan, :start]` | `system_time` | `patterns_checked` |
| `[:sigil_guard, :scan, :stop]` | `duration` | `hit_count`, `patterns_checked` |
| `[:sigil_guard, :registry, :fetch, :start]` | `system_time` | `url` |
| `[:sigil_guard, :registry, :fetch, :stop]` | `duration` | `count`, `source` |
| `[:sigil_guard, :policy, :decision]` | `system_time` | `action`, `risk_level`, `trust_level` |
| `[:sigil_guard, :audit, :logged]` | `system_time` | `event_type`, `actor` |

## Configuration

```elixir
config :sigil_guard,
  backend: :elixir,                        # :elixir | :nif
  registry_url: "https://registry.sigil-protocol.org",
  registry_ttl_ms: :timer.hours(1),
  registry_timeout_ms: 5_000,
  registry_enabled: false,
  scanner_patterns: :built_in
```

### Backend Selection

```elixir
# Check available backends
SigilGuard.Backend.available_backends()
#=> [:elixir] or [:elixir, :nif]

# Get current backend module
SigilGuard.Backend.impl()
#=> SigilGuard.Backend.Elixir
```

## Common Patterns

### Scanning and Redaction

```elixir
{:ok, "safe text"} = SigilGuard.scan("safe text")
{:hit, hits} = SigilGuard.scan("AKIAIOSFODNN7EXAMPLE")
redacted = SigilGuard.scan_and_redact("key=AKIAIOSFODNN7EXAMPLE")
```

### Envelope Signing

```elixir
envelope = SigilGuard.Envelope.sign("did:sigil:abc", :allowed, signer: MySigner)
:ok = SigilGuard.Envelope.verify(envelope, public_key_b64u)
```

### Policy Evaluation

```elixir
:allowed = SigilGuard.policy_verdict("read_file", :authenticated)
:blocked = SigilGuard.policy_verdict("delete_database", :anonymous)
```

## References

- [SIGIL Protocol](https://sigil-protocol.org/)
- [SIGIL Registry](https://registry.sigil-protocol.org/)
- [Rustler](https://github.com/rusterlium/rustler)
