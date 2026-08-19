# SigilGuard

**In-process. OTP-supervised. Deterministic. No sidecar. Signed evidence.**

[![Hex.pm](https://img.shields.io/hexpm/v/sigil_guard.svg)](https://hex.pm/packages/sigil_guard)
[![Docs](https://img.shields.io/badge/docs-hexdocs-blue.svg)](https://hexdocs.pm/sigil_guard)
[![CI](https://github.com/refpath/sigil_guard/actions/workflows/ci.yml/badge.svg)](https://github.com/refpath/sigil_guard/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/refpath/sigil_guard/branch/main/graph/badge.svg)](https://codecov.io/gh/refpath/sigil_guard)
[![License](https://img.shields.io/github/license/refpath/sigil_guard.svg)](LICENSE)

[Installation](#installation) ·
[Quick Start](#quick-start) ·
[Livebook Tutorials](#livebook-tutorials) ·
[Agent Trust Profile](#agent-trust-profile) ·
[Agent Trust Gateway](#agent-trust-gateway) ·
[Configuration](#configuration) ·
[Capabilities](#capabilities) ·
[Architecture](docs/README.md)

---

SigilGuard is an embedded security runtime for MCP v2 and agent-tool
boundaries, in native Elixir. MCP specifications are date-versioned; throughout
this project, “MCP v2” means the final `2026-07-28` revision. SigilGuard sits
between a language model and the tools it can reach, decides whether a tool
call, a tool result, or a model output may cross a boundary, and produces
signed, tamper-evident evidence of every decision. It runs in-process on the
BEAM: no sidecar, no proxy hop, no network call on the decision path.

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
| **MCP v2 / tool gateway** | Transport-agnostic guards for MCP `2026-07-28` structured requests, MRTR results, and manifests pinned by digest. |
| **Signed attestations** | Canonical, DSSE-enveloped statements binding an actor, tool, action, payload, and context to a verdict. |
| **Trust bundles** | Signed, local trust material — roots, keys, policies, patterns, tool manifests, and revocations — verified offline. |
| **Confirmation tokens** | Short-lived human-approval grants bound to the exact action, payload, and context, never a fuzzy intent. |
| **Streaming sanitizer** | Chunk-safe holdback so a secret split across output chunks is never emitted early. |
| **Tamper-evident audit** | HMAC-linked event chains, Merkle checkpoints with inclusion and consistency proofs, signed exports, and external anchoring. |
| **Agent-to-agent trust** | Signed agent cards and delegation-chain validation for inter-agent calls. |
| **Vault** | AES-256-GCM secret storage behind a swappable behaviour (KMS, HSM, external vault). |
| **Telemetry** | `:telemetry` events plus OpenTelemetry-style attribute mapping for every decision. |

## Installation

SigilGuard 1.0 requires Elixir 1.18 or later.

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

## Livebook Tutorials

The executable [Livebook tutorial track](notebooks/README.md) teaches the
complete public surface as one agent-security story. It starts with scanner and
boundary fundamentals, puts an optional live ReqLLM proposal behind a
host-owned tool callback, and continues through manifests, confirmations,
attestations, MCP v2/Apps, streaming, trust bundles, agent-to-agent trust, and
portable audit evidence.

Every chapter also runs without a provider or network connection. The AI
chapter uses a deterministic adversarial replay by default, so the security
result remains repeatable during a talk; a Livebook `OPENAI_API_KEY` secret
enables the optional live proposal without giving the model authority to run
the callback.

```bash
mix sigil.livebook_check
```

Start with [An AI Agent Under Attack](notebooks/ai-agent-under-attack.livemd)
for the conference demo, or follow the full self-study path from the tutorial
catalog.

## Agent Trust Profile

The 1.0 release line has one wire profile: `sigil_guard_agent_trust/v1`.
Agent Trust evidence is a DSSE envelope over a JCS-canonical in-toto-style
statement, with payload and context digests bound to the boundary decision.
The public metadata keys are:

| Key | Purpose |
|-----|---------|
| `_agent_trust` | Carries an Agent Trust attestation envelope for a tool request or result. |
| `_agent_confirmation` | Carries a short-lived confirmation token for a confirm-required action. |
| `confirmation_token` | Compatibility-neutral token field for hosts that do not want a SigilGuard-prefixed metadata name. |

`SigilGuard.Attestation.strip_metadata/1` removes those keys at the payload
root and inside `params` before digest computation, in atom and string forms.
All other fields are ordinary user payload.

## Agent Trust Gateway

`SigilGuard.ToolGateway` is the 1.0 entry point for MCP-shaped tool calls and
tool results. It combines capability-manifest checks, boundary policy,
confirmation tokens, and Agent Trust attestations.

Start with `SigilGuard.ToolGateway` when your host already owns the request and
result maps and wants the full enforcement surface. Use `SigilGuard.MCP.Gateway`
when wiring an MCP transport that wants JSON-RPC-compatible helper names and
tuple responses; it is a thin permanent facade over `ToolGateway`.

Guard a tool request against a pinned manifest:

```elixir
request = %{
  "method" => "tools/call",
  "params" => %{
    "name" => "repo_file_write",
    "arguments" => %{"path" => "README.md", "content" => "updated"},
    "_meta" => %{
      "io.modelcontextprotocol/protocolVersion" => "2026-07-28",
      "io.modelcontextprotocol/clientCapabilities" => %{}
    }
  }
}

context = [
  actor: "spiffe://agents/editor",
  trust_level: :medium,
  sandbox_id: "sandbox-123",
  isolation_level: :container
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
    payload: request,
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

### MCP v2 (`2026-07-28`) and MCP Apps

SigilGuard does not negotiate MCP or own a transport. A host adapter selects
MCP v2 response behavior with `protocol_version: "2026-07-28"` or supplies the
standard per-request protocol-version `_meta` value. The adapter must also
supply and validate the required client-capabilities metadata. Missing
per-request fields use `-32602`; missing declared capabilities and unsupported
revisions use MCP's `-32021` and `-32022` errors. Successful v2 results receive
`resultType: "complete"` when absent and preserve every existing discriminator
for host-side validation. Unknown future revisions are not treated as v2.
`input_required`, `inputRequests`, `inputResponses`, and `requestState` remain
part of the exact structured confirmation and attestation binding.

Capability manifests use `sigil_guard_capability_manifest/v2`. The v2 digest
also binds optional tool `title`, `icons`, normalized MCP Apps UI metadata, and
validated `x-mcp-header` annotations. Header annotations must be on
`properties`-reachable `boolean`, `integer`, or `string` fields; header names
are HTTP tokens, case-insensitively unique, and may not expose sensitive
parameters. Icon sources must be HTTPS or valid image data URLs. The host
adapter owns same-origin credential-free icon fetching, redirect and size
limits, content sniffing and safe rendering, complete JSON Schema 2020-12
validation, JavaScript-safe integer checks at runtime, header construction, and
MCP `HeaderMismatch` handling.
App-origin tool calls use `origin: :app` and must name the same trusted
`mcp_server` as an app-visible manifest.

Before a renderer receives an MCP Apps resource, verify its pinned bytes and
requested browser capabilities:

```elixir
{:ok, verified_resource} =
  SigilGuard.MCP.AppResource.verify(resource,
    expected_uri: "ui://repo/review",
    expected_sha256: pinned_ui_sha256,
    max_bytes: 1_048_576,
    allowed_connect_domains: ["https://api.example.com"],
    allowed_permissions: [:clipboardWrite]
  )
```

Resource verification is capped at 1 MiB by default. Dedicated app domains use
the host-defined format and must match `:allowed_app_domains` exactly. The host
remains responsible for `server/discover`, `subscriptions/listen`, OAuth,
transport headers, HTML5 validation, iframe creation, sandbox attributes, and
CSP enforcement. The stable MCP Apps extension predates MCP v2, so the host
maps its negotiated UI capability into v2 per-request metadata and discovery;
SigilGuard only enforces the resulting boundary metadata.

See [Migrating to MCP v2](MIGRATING-1.0.md#mcp-v2-2026-07-28).

## Configuration

Stateful features are initialized automatically by `SigilGuard.Runtime`, which
provides stable ownership for replay, rate-limit, and trust-bundle ETS state.
The default setup uses application environment:

```elixir
config :sigil_guard,
  trust_bundle: {:priv, :my_app, "sigil/trust_bundle.json"},
  scanner_patterns: :bundle,
  attestation_ttl_ms: 300_000,
  max_skew_ms: 60_000,
  replay_ttl_ms: 300_000
```

Hosts that need control over failure placement or want to avoid global
configuration can disable automatic startup and supervise the runtime directly:

```elixir
config :sigil_guard, runtime: false

children = [
  {SigilGuard.Runtime,
   config: [
     runtime: false,
     trust_bundle: {:priv, :my_app, "sigil/trust_bundle.json"},
     scanner_patterns: :bundle,
     attestation_ttl_ms: 300_000,
     max_skew_ms: 60_000,
     replay_ttl_ms: 300_000
   ]}
]

Supervisor.start_link(children, strategy: :one_for_one)
```

Unknown keys and removed legacy keys fail runtime startup with
`SigilGuard.ConfigError` and a pointer to `MIGRATING-1.0.md`. Omitting the
runtime child's `:config` option makes it read the `:sigil_guard` application
environment.

| Key | Default | Purpose |
|-----|---------|---------|
| `:runtime` | `true` | Start the singleton runtime automatically; set `false` for caller-owned supervision. |
| `:trust_bundle` | `:none` | Local trust-bundle source: `:none`, `{:file, path}`, `{:priv, app, path}`, `{:map, map}`, or `{:binary, bytes}`. |
| `:scanner_patterns` | `:built_in` | Pattern source, either `:built_in` or `:bundle`; `:bundle` requires `:trust_bundle`. |
| `:http_client` | `nil` | Host-provided module implementing `SigilGuard.HTTPClient` for audit anchor HTTP stores. |
| `:attestation_ttl_ms` | `300_000` | Attestation lifetime in milliseconds. |
| `:max_skew_ms` | `60_000` | Maximum accepted clock skew in milliseconds. |
| `:replay_ttl_ms` | `300_000` | Replay cache lifetime in milliseconds. |
| `:vault_master_key` | `nil` | Optional base64-encoded key for `SigilGuard.Vault.InMemory`. |
| `:trust_mappings` | `[]` | Ordered `{pattern, trust_level}` actor mappings; patterns are exact strings or one trailing `*`. |

Configured trust bundles are loaded and verified when `SigilGuard.Runtime`
starts. Verified snapshots are cached for the current BEAM boot in the
`:sigil_guard_trust_bundle` ETS table, along with rollback floors, root pins,
rotation digests, and revoked key ids. The signed bundle remains the durable
source of truth across boots; remote distribution, if needed, belongs to the
host application before bytes are passed to `SigilGuard.TrustBundle.load/2`.
Trust-bundle roles always carry their declared threshold. For compatibility,
the 1.0 release line uses an effective threshold of `1` unless verification is
called with `enforce_declared_threshold: true`; root rotation documents always
enforce the full declared old-root and new-root thresholds.

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
./bin/check           # clean-clone-safe full quality gate
mix docs             # generate documentation
mix bench            # run benchmarks
mix sigil_guard.sbom --output dist/sigil_guard.spdx.json
```

The full gate fetches the locked dependency graph, checks the production build
and Hex package, and then enforces coverage at or above 95% plus the repository's
security, documentation, type, and migration checks. Security modules carry
negative, tamper, replay, expiration, and malformed-input tests.

## Architecture

The [architecture overview](docs/README.md) maps the component layers, the
module topology, and the runtime, MCP, and audit-evidence flows, with diagrams.

## References

- [Model Context Protocol v2 — 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28)
- [MCP Apps extension](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Historical upstream SIGIL repository](https://github.com/sigil-eu/sigil)

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines.

## License

SigilGuard is released under the MIT License. See [LICENSE](LICENSE).
