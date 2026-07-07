# SigilGuard

**In-process. OTP-supervised. Deterministic. No sidecar. Signed evidence.**

[![Hex.pm](https://img.shields.io/hexpm/v/sigil_guard.svg)](https://hex.pm/packages/sigil_guard)
[![Docs](https://img.shields.io/badge/docs-hexdocs-blue.svg)](https://hexdocs.pm/sigil_guard)
[![CI](https://github.com/futhr/sigil_guard/actions/workflows/ci.yml/badge.svg)](https://github.com/futhr/sigil_guard/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/futhr/sigil_guard/branch/main/graph/badge.svg)](https://codecov.io/gh/futhr/sigil_guard)
[![License](https://img.shields.io/github/license/futhr/sigil_guard.svg)](LICENSE)

[Installation](#installation) ·
[Quick Start](#quick-start) ·
[Agent Trust Profile](#agent-trust-profile) ·
[Agent Trust Gateway](#agent-trust-gateway) ·
[Configuration](#configuration) ·
[Capabilities](#capabilities) ·
[Architecture](docs/README.md)

---

SigilGuard is an embedded security runtime for MCP and agent-tool boundaries,
in native Elixir. It sits between a language model and the tools it can reach,
decides whether a tool call, a tool result, or a model output is allowed to
cross a given boundary, and produces signed, tamper-evident evidence of every
decision. It runs in-process on the BEAM: no sidecar, no proxy hop, no network
call on the decision path.

The problem it addresses is the one every agent deployment eventually hits: a
model with access to private data, exposure to untrusted content, and the
ability to act or communicate outward is one poisoned tool description or
prompt-injected result away from doing real damage. Model-level guardrails help
but are probabilistic. SigilGuard is the deterministic layer underneath: signed
trust material, capability manifests pinned by digest, source-to-sink policy,
and human-in-the-loop confirmation bound to the exact action.

## Why embedded

The common answer to MCP security is a proxy, a gateway, or a cloud scanner: a
separate service in the request path. That buys latency, an extra operational
surface, and a trust boundary of its own. For a team already on Elixir, an
in-process library is a better fit.

- **Deterministic core.** Policy decisions are code, not a model call. Same
  inputs, same verdict, every time.
- **Signed evidence, locally.** A tamper-evident HMAC and Merkle audit chain,
  with signed checkpoints, inclusion and consistency proofs, and portable
  exports, held in your app rather than a vendor's log.
- **No sidecar.** OTP-supervised, sub-millisecond on the decision path, and
  offline by default. Trust material ships with your release.

## Capabilities

| Capability | What it does |
|------------|--------------|
| **Sensitivity scanner** | Staged detection and redaction of secrets and credentials, with confidence scoring and boundary-aware enrichment. |
| **Boundary policy kernel** | Deterministic source-to-sink decisions over phase, origin, sink, actor, trust zone, and sandbox identity. |
| **MCP / tool gateway** | Transport-agnostic guards for tool requests and results, with capability manifests pinned by digest. |
| **Signed attestations** | Canonical, DSSE-enveloped statements binding an actor, tool, action, payload, and context to a verdict. |
| **Trust bundles** | Signed, local trust material — roots, keys, policies, patterns, tool manifests, and revocations — verified offline. |
| **Confirmation tokens** | Short-lived human-approval grants bound to the exact action, payload, and context, never a fuzzy intent. |
| **Streaming sanitizer** | Chunk-safe holdback so a secret split across output chunks is never emitted early. |
| **Tamper-evident audit** | HMAC-linked event chains, Merkle checkpoints with inclusion and consistency proofs, signed exports, and external anchoring. |
| **Agent-to-agent trust** | Signed agent cards and delegation-chain validation for inter-agent calls. |
| **Vault** | AES-256-GCM secret storage behind a swappable behaviour (KMS, HSM, external vault). |
| **Telemetry** | `:telemetry` events plus OpenTelemetry-style attribute mapping for every decision. |

## Installation

SigilGuard v3 requires Elixir 1.18 or later.

```elixir
def deps do
  [
    {:sigil_guard, "~> 1.0"}
  ]
end
```

## Quick Start

The core is a single decision function. Give it a payload and the boundary it
is crossing; it returns a `Decision`.

```elixir
# Block a secret leaving the runtime toward an external sink.
decision =
  SigilGuard.guard("AWS_KEY=AKIAIOSFODNN7EXAMPLE",
    phase: :tool_request,
    origin: :model,
    sink: :external,
    tool: "send_webhook",
    trust_level: :high
  )

:block = decision.action

# Redact before the same content reaches the model.
decision =
  SigilGuard.guard("token=supersecretvalue123",
    phase: :inbound_user,
    origin: :user,
    sink: :model,
    trust_level: :medium
  )

:redact = decision.action
"token=[SECRET]" = decision.sanitized_text
```

Scanning and policy are also available on their own:

```elixir
{:ok, "safe text"} = SigilGuard.scan("safe text")
{:hit, _hits} = SigilGuard.scan("AKIAIOSFODNN7EXAMPLE")
"key=[AWS_KEY]" = SigilGuard.scan_and_redact("key=AKIAIOSFODNN7EXAMPLE")

:allowed = SigilGuard.policy_verdict("read_file", :medium)
:blocked = SigilGuard.policy_verdict("delete_database", :low)
{:confirm, _reason} = SigilGuard.policy_verdict("create_user", :low)
```

The gate is transport-agnostic: an MCP server, an agent loop, or a gateway
calls it before tool execution, after tool results, and before outbound writes,
without pulling any specific MCP adapter into the core. The MCP gateway,
attestation signing, confirmation flow, trust bundles, and audit chain build on
this same decision. The [architecture](docs/README.md) covers the full surface.

## Agent Trust Profile

V3 has one wire profile: `sigil_guard_agent_trust/v1`. Agent Trust evidence is
a DSSE envelope over a JCS-canonical in-toto-style statement, with payload and
context digests bound to the boundary decision. The public metadata keys are:

| Key | Purpose |
|-----|---------|
| `_agent_trust` | Carries an Agent Trust attestation envelope for a tool request or result. |
| `_agent_confirmation` | Carries a short-lived confirmation token for a confirm-required action. |
| `confirmation_token` | Compatibility-neutral token field for hosts that do not want a SigilGuard-prefixed metadata name. |

`SigilGuard.Attestation.strip_metadata/1` removes those keys at the payload
root and inside `params` before digest computation, in atom and string forms.
All other fields are ordinary user payload.

## Agent Trust Gateway

`SigilGuard.ToolGateway` is the v3 entry point for MCP-shaped tool calls and
tool results. It combines capability-manifest checks, boundary policy,
confirmation tokens, and Agent Trust attestations.

Guard a tool request against a pinned manifest:

```elixir
request = %{
  "method" => "tools/call",
  "params" => %{
    "name" => "repo_file_write",
    "arguments" => %{"path" => "README.md", "content" => "updated"}
  }
}

context = [
  actor: "spiffe://agents/editor",
  trust_level: :medium,
  sandbox_id: "sandbox-123",
  isolation_level: :filesystem
]

decision =
  SigilGuard.ToolGateway.guard_request(request, context,
    manifests: %{"repo_file_write" => pinned_manifest},
    require_manifest: true
  )
```

Attach and require Agent Trust evidence with the `_agent_trust` metadata key:

```elixir
{:ok, envelope} =
  SigilGuard.ToolGateway.attest_request(decision, context,
    signer: MyApp.AgentSigner,
    keyid: "agent-ed25519-1",
    nonce: "unique-request-nonce",
    manifest: pinned_manifest
  )

trusted_request = SigilGuard.Attestation.attach(request, envelope)

verified =
  SigilGuard.ToolGateway.guard_request(trusted_request, context,
    manifests: %{"repo_file_write" => pinned_manifest},
    attestation: :required,
    trust_material: %{"agent-ed25519-1" => agent_public_key}
  )
```

Confirmation tokens use `_agent_confirmation` when a decision requires human
approval:

```elixir
{:ok, token} =
  SigilGuard.ToolGateway.issue_confirmation(
    request,
    context,
    decision,
    confirmation_key,
    manifest: pinned_manifest
  )

confirmed_request = SigilGuard.Attestation.attach_confirmation(request, token)

confirmed =
  SigilGuard.ToolGateway.guard_request(confirmed_request, context,
    manifests: %{"repo_file_write" => pinned_manifest},
    confirmation_key: confirmation_key
  )
```

## Configuration

All configuration lives under the `:sigil_guard` application environment and is
validated at boot. Unknown keys and removed v2 keys fail closed with
`SigilGuard.ConfigError` and a pointer to `MIGRATING-1.0.md`.

```elixir
config :sigil_guard,
  trust_bundle: {:priv, :my_app, "sigil/trust_bundle.json"},
  scanner_patterns: :bundle,
  attestation_ttl_ms: 300_000,
  max_skew_ms: 60_000,
  replay_ttl_ms: 300_000
```

| Key | Default | Purpose |
|-----|---------|---------|
| `:trust_bundle` | `:none` | Local trust-bundle source: `:none`, `{:file, path}`, `{:priv, app, path}`, `{:map, map}`, or `{:binary, bytes}`. |
| `:scanner_patterns` | `:built_in` | Pattern source, either `:built_in` or `:bundle`; `:bundle` requires `:trust_bundle`. |
| `:http_client` | `nil` | Host-provided module implementing `SigilGuard.HTTPClient` for audit anchor HTTP stores. |
| `:attestation_ttl_ms` | `300_000` | Attestation lifetime in milliseconds. |
| `:max_skew_ms` | `60_000` | Maximum accepted clock skew in milliseconds. |
| `:replay_ttl_ms` | `300_000` | Replay cache lifetime in milliseconds. |
| `:vault_master_key` | `nil` | Optional base64-encoded key for `SigilGuard.Vault.InMemory`. |
| `:trust_mappings` | `[]` | Ordered `{pattern, trust_level}` actor mappings; patterns are exact strings or one trailing `*`. |

Configured trust bundles are loaded and verified at application boot. Verified
snapshots are cached for the current BEAM boot in the
`:sigil_guard_trust_bundle` ETS table, along with rollback floors, root pins,
rotation digests, and revoked key ids. The signed bundle remains the durable
source of truth across boots; remote distribution, if needed, belongs to the
host application before bytes are passed to `SigilGuard.TrustBundle.load/2`.

## Extension Points

Host applications own their transports, auth, storage, and deployment.
SigilGuard plugs into them through behaviours:

| Behaviour | Purpose | Typical implementation |
|-----------|---------|------------------------|
| `SigilGuard.Signer` | Cryptographic signing | HSM, KMS, cloud key management |
| `SigilGuard.Vault` | Encrypted storage | HashiCorp Vault, AWS KMS, database |
| `SigilGuard.Audit.Logger` | Audit persistence | Database, file, external service |
| `SigilGuard.Identity` | Trust and identity context | Your auth system |
| `SigilGuard.HTTPClient` | Outbound HTTP for anchor stores | Req or your own client |

## Telemetry

SigilGuard emits `:telemetry` events for scanning, gate decisions, MCP
requests, policy verdicts, trust-bundle verification, and audit logging. Each
decision event carries the sanitized boundary metadata — phase, actor, origin,
sink, tool, trust zone, verdict, and digests — with raw payloads kept out by
default. Use `SigilGuard.Telemetry.otel_attributes/3` to map them into
OpenTelemetry-style attributes under the `sigilguard.*` namespace.

## Development

```bash
mix setup            # install dependencies
mix test             # run tests
mix lint             # format + Credo + Dialyzer
mix check            # full quality gate
mix docs             # generate documentation
mix bench            # run benchmarks
mix sigil_guard.sbom --output dist/sigil_guard.spdx.json
```

Coverage is held at or above 95%, and security modules carry negative, tamper,
replay, expiration, and malformed-input tests.

## Architecture

The [architecture overview](docs/README.md) maps the component layers, the
module topology, and the runtime, MCP, and audit-evidence flows, with diagrams.

## References

- [Model Context Protocol — Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Historical upstream SIGIL repository](https://github.com/sigil-eu/sigil)

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines.

## License

SigilGuard is released under the MIT License. See [LICENSE](LICENSE).
