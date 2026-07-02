# SigilGuard

**Embedded security runtime for MCP and agent-tool boundaries, in native Elixir.**

[![Hex.pm](https://img.shields.io/hexpm/v/sigil_guard.svg)](https://hex.pm/packages/sigil_guard)
[![Docs](https://img.shields.io/badge/docs-hexdocs-blue.svg)](https://hexdocs.pm/sigil_guard)
[![CI](https://github.com/futhr/sigil_guard/actions/workflows/ci.yml/badge.svg)](https://github.com/futhr/sigil_guard/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/futhr/sigil_guard/branch/main/graph/badge.svg)](https://codecov.io/gh/futhr/sigil_guard)
[![License](https://img.shields.io/github/license/futhr/sigil_guard.svg)](LICENSE)

[Installation](#installation) ·
[Quick Start](#quick-start) ·
[Architecture](https://github.com/futhr/sigil_guard/blob/main/docs/README.md) ·
[Roadmap](#status-and-roadmap)

---

SigilGuard sits between a language model and the tools it can reach. It decides
whether a tool call, a tool result, or a model output is allowed to cross a
given boundary — and it produces signed, tamper-evident evidence of every
decision. It runs in-process on the BEAM: no sidecar, no proxy hop, no network
call on the decision path.

The problem it addresses is the one every agent deployment eventually hits: a
model with access to private data, exposure to untrusted content, and the
ability to act or communicate outward is one poisoned tool description or
prompt-injected result away from doing real damage. Model-level guardrails help
but are probabilistic. SigilGuard adds the deterministic layer underneath —
signed trust material, capability manifests pinned by digest, source-to-sink
policy, and human-in-the-loop confirmation bound to the exact action.

## Why embedded

The market answer to MCP security is mostly proxies, gateways, and cloud
scanners — a separate service in the request path. That buys latency, an extra
operational surface, and a trust boundary of its own. For a team already on
Elixir, an in-process library is a better fit:

- **Deterministic core.** Policy decisions are code, not a model call. Same
  inputs, same verdict, every time.
- **Signed evidence, locally.** A tamper-evident HMAC + Merkle audit chain with
  signed checkpoints and portable exports, held in your app — not a vendor's log.
- **No sidecar.** OTP-supervised, sub-millisecond on the decision path, and
  offline by default. Trust material ships with your release.

## Status and Roadmap

The `0.2.x` line is the current released series. The next major release,
**v3.0 — the Agent Trust Profile**, is a deliberate breaking rewrite around
signed attestations, embedded trust bundles, capability manifests, a
deterministic boundary policy kernel, agent-to-agent trust, and verifiable
audit evidence.

The v3 design is complete and documented: the
[architecture map](https://github.com/futhr/sigil_guard/blob/main/docs/README.md),
the [specs](https://github.com/futhr/sigil_guard/blob/main/docs/specs/README.md)
(`SP.01`–`SP.15`), the
[research and decisions](https://github.com/futhr/sigil_guard/blob/main/docs/research/README.md)
(`R.01`–`R.07`), and the
[execution checklist](https://github.com/futhr/sigil_guard/blob/main/docs/tasks/sigil-tasks.md).
The consumer-facing API shown below is stable and carries forward unchanged;
migration for the surfaces that do change will ship as `MIGRATING-3.0.md`.

## Capabilities

| Capability | What it does |
|------------|--------------|
| **Sensitivity scanner** | Staged detection and redaction of secrets and credentials, with confidence and boundary-aware enrichment. |
| **Boundary policy kernel** | Deterministic source-to-sink decisions over phase, origin, sink, actor, trust zone, and sandbox identity. |
| **MCP / tool gateway** | Transport-agnostic guards for tool requests and results, with capability manifests pinned by digest. |
| **Confirmation tokens** | Short-lived human-approval grants bound to the exact action, payload, and context — never a fuzzy intent. |
| **Streaming sanitizer** | Chunk-safe holdback so a secret split across output chunks is never emitted early. |
| **Tamper-evident audit** | HMAC-linked event chains, Merkle checkpoints with inclusion/consistency proofs, signed exports, and external anchoring. |
| **Trust bundles** | Signed, local trust material — roots, keys, policies, patterns, tool manifests, and revocations — verified offline. |
| **Agent-to-agent trust** | Signed agent cards and delegation-chain validation for inter-agent calls. |
| **Vault** | AES-256-GCM secret storage behind a swappable behaviour (KMS, HSM, external vault). |
| **Telemetry** | `:telemetry` events plus OpenTelemetry-style attribute mapping for every decision. |

## Installation

```elixir
def deps do
  [
    {:sigil_guard, "~> 0.2"}
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

:blocked = decision.verdict
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
attestation signing, confirmation flow, and audit chain build on this same
decision — see the [architecture map](https://github.com/futhr/sigil_guard/blob/main/docs/README.md)
and the [specs](https://github.com/futhr/sigil_guard/blob/main/docs/specs/README.md)
for the full surface.

## Extension Points

Host applications own their transports, auth, storage, and deployment.
SigilGuard plugs into them through behaviours:

| Behaviour | Purpose | Typical implementation |
|-----------|---------|------------------------|
| `SigilGuard.Signer` | Cryptographic signing | HSM, KMS, cloud key management |
| `SigilGuard.Vault` | Encrypted storage | HashiCorp Vault, AWS KMS, database |
| `SigilGuard.Audit.Logger` | Audit persistence | Database, file, external service |
| `SigilGuard.Identity` | Trust and identity context | Your auth system |

## Telemetry

SigilGuard emits `:telemetry` events for scanning, gate decisions, MCP
requests, policy verdicts, and audit logging. Each decision event carries the
sanitized boundary metadata — phase, actor, origin, sink, tool, trust zone,
verdict, and digests — with raw payloads kept out by default. Use
`SigilGuard.Telemetry.otel_attributes/3` (or `attach_otel_forwarder/3`) to map
them into OpenTelemetry-style attributes.

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

## Documentation

- [Architecture map](https://github.com/futhr/sigil_guard/blob/main/docs/README.md) — module topology, boundary flows, and the v3 design.
- [Specs](https://github.com/futhr/sigil_guard/blob/main/docs/specs/README.md) — the implementable `SP.01`–`SP.15` contracts.
- [Research](https://github.com/futhr/sigil_guard/blob/main/docs/research/README.md) — decisions and their primary sources.
- [Task list](https://github.com/futhr/sigil_guard/blob/main/docs/tasks/sigil-tasks.md) — the v3 execution checklist and decision log.

## References

- [Model Context Protocol — Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Historical upstream SIGIL repository](https://github.com/sigil-eu/sigil)

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines.

## License

SigilGuard is released under the MIT License. See [LICENSE](LICENSE).
