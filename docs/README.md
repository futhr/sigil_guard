# SigilGuard Architecture Index

This is the canonical codebase and planning map. The root `README.md` is the
quickstart and package overview; this file owns architecture, implemented
contracts, planned v3 Agent Trust work, and the documentation index.

## Reading Order

| Need | Start Here |
|------|------------|
| Product overview and examples | [`../README.md`](../README.md) |
| Current architecture map | [Existing Codebase](#existing-codebase) |
| Runtime and MCP flow | [Boundary Flows](#boundary-flows) |
| Forward architecture | [V3 Agent Trust Profile](#v3-agent-trust-profile) |
| Concrete work list | [`tasks/sigil-tasks.md`](tasks/sigil-tasks.md) |
| Research rationale | [`research/README.md`](research/README.md) (R.01 strategy, R.02-R.07 decisions) |
| Implementable specs | [Spec Catalogue](#spec-catalogue) |

## Design Position

SigilGuard is an embedded native-Elixir security runtime. It does not depend on
a hosted registry, a Rust/NIF backend, or a live upstream protocol service.
The v2/foundation code still contains old SIGIL-shaped wire fields and
registry-named modules. V3 should replace those public surfaces with the
SigilGuard Agent Trust Profile: local signed trust bundles, canonical agent/MCP
attestations, deterministic boundary policy, staged scanning, quarantine, and
exportable audit evidence.

## Existing Codebase

```mermaid
flowchart TD
    Host[Host app or adapter]
    API[SigilGuard public API]
    Backend[Backend.Elixir]

    Host --> API --> Backend

    Backend --> Scanner[Scanner]
    Scanner --> Pipeline[Scanner.Pipeline]
    Scanner --> Patterns[Patterns]

    Backend --> Envelope[Envelope]
    Envelope --> Profile[Profile]
    Envelope --> Replay[ReplayStore]
    Envelope --> Signer[Signer / Signer.Ed25519]

    Backend --> Policy[Policy]
    Policy --> Identity[Identity]

    API --> Gate[Runtime.Gate]
    Gate --> Context[Context]
    Gate --> Decision[Decision]
    Gate --> Quarantine[Quarantine]
    Gate --> RepoPolicy[RepoPolicy]
    RepoPolicy --> RepoDecision[RepoPolicy.Decision]

    API --> Stream[Runtime.Stream]
    Stream --> Gate

    API --> MCP[MCP.Gateway]
    MCP --> Gate
    MCP --> Envelope
    MCP --> Confirmation[Confirmation]
    Confirmation --> Replay

    API --> Audit[Audit]
    Audit --> Checkpoint[Audit.Checkpoint]
    Audit --> Anchor[Audit.Anchor]
    Anchor --> AnchorStore[Audit.Anchor.Store]
    AnchorStore --> HTTPAnchor[Store.HTTP]
    AnchorStore --> LocalAnchor[Store.LocalFile]
    Anchor --> Receipt[Audit.Anchor.Receipt]
    Checkpoint --> Export[Audit.Export]

    API --> Vault[Vault]
    Vault --> InMemoryVault[Vault.InMemory]
    Vault --> VaultEntry[Vault.Entry]

    API --> LegacyRemote[Registry legacy adapter]
    LegacyRemote --> Bundle[Registry.Bundle]
    LegacyRemote --> Cache[Registry.Cache]
    LegacyRemote --> Patterns

    API --> Config[Config]
    API --> Telemetry[Telemetry]
```

### Existing Module Groups

| Group | Modules | Contract Spec |
|-------|---------|---------------|
| Native backend and envelopes | `SigilGuard`, `Backend`, `Backend.Elixir`, `Envelope`, `Profile`, `ReplayStore`, `Signer` | [`SP.06`](specs/SP.06-envelope-and-native-backend-contracts.md) |
| Runtime boundary checks | `Context`, `Decision`, `Runtime.Gate`, `Runtime.Stream`, `Scanner`, `Scanner.Pipeline`, `Quarantine` | [`SP.07`](specs/SP.07-runtime-gate-and-streaming-contracts.md) |
| MCP and approvals | `MCP.Gateway`, `Confirmation` | [`SP.08`](specs/SP.08-mcp-gateway-and-confirmation-contracts.md) |
| Audit evidence | `Audit`, `Audit.Checkpoint`, `Audit.Anchor`, `Audit.Anchor.Store`, `Audit.Export` | [`SP.09`](specs/SP.09-audit-chain-and-anchor-contracts.md) |
| Vault and identity | `Vault`, `Vault.InMemory`, `Vault.Entry`, `Identity`, `Identity.Binding` | [`SP.10`](specs/SP.10-vault-and-identity-contracts.md) |
| Repo policy | `RepoPolicy`, `RepoPolicy.Decision` | [`SP.11`](specs/SP.11-repo-policy-kernel-contracts.md) |
| Legacy remote removal | `Registry`, `Registry.Bundle`, `Registry.Cache` | [`SP.12`](specs/SP.12-legacy-remote-bundle-adapter-contracts.md) |

## Boundary Flows

### Runtime Gate

```mermaid
sequenceDiagram
    participant Host
    participant Gate as Runtime.Gate
    participant Context
    participant Scanner
    participant Quarantine
    participant Repo as RepoPolicy
    participant Policy
    participant Telemetry

    Host->>Gate: payload + boundary context
    Gate->>Context: normalize and validate
    Gate->>Scanner: extract and validate sensitive signals
    Gate->>Quarantine: inspect prompt/tool poisoning indicators
    Gate->>Repo: optional repo path policy
    Gate->>Policy: risk + trust-level decision
    Gate->>Telemetry: emit sanitized metadata
    Gate-->>Host: Decision allow/block/redact/confirm
```

### MCP Gateway

```mermaid
sequenceDiagram
    participant Adapter as Host MCP adapter
    participant Gateway as MCP.Gateway
    participant Envelope
    participant Gate as Runtime.Gate
    participant Confirm as Confirmation
    participant Tool

    Adapter->>Gateway: MCP-shaped tools/call request
    Gateway->>Envelope: optional existing envelope verification
    Gateway->>Gate: normalized request boundary
    Gate-->>Gateway: Decision
    alt allowed
        Gateway->>Tool: execute
        Tool-->>Gateway: tool result
        Gateway->>Gate: tool-result-to-model boundary
        Gate-->>Gateway: result decision
        Gateway-->>Adapter: result or sanitized result
    else confirm required
        Gateway-->>Adapter: JSON-RPC confirmation error
        Adapter->>Confirm: issue action-bound token
        Adapter->>Gateway: request + token
        Gateway->>Confirm: verify exact action digest
        Gateway-->>Adapter: confirmed decision
    else blocked
        Gateway-->>Adapter: JSON-RPC block/quarantine error
    end
```

### Audit Evidence

```mermaid
flowchart LR
    Event[Audit event] --> HMAC[HMAC chain]
    HMAC --> Checkpoint[Merkle checkpoint]
    Checkpoint --> Signature[Ed25519 checkpoint signature]
    Checkpoint --> Anchor[External anchor record]
    Anchor --> Receipt[Signed receipt]
    Signature --> Export[Portable audit export]
    Receipt --> Export
```

## V3 Agent Trust Profile

The planned architecture keeps useful native-Elixir foundations while replacing
legacy public protocol surfaces with Agent Trust APIs and migration docs.

```mermaid
flowchart TD
    SP01[SP.01 Agent Trust Profile]
    SP02[SP.02 Embedded Trust Bundles]
    SP03[SP.03 MCP And Tool Gateway]
    SP04[SP.04 Boundary Scanner and Policy Kernel]
    SP05[SP.05 Audit and Release Provenance]
    SP13[SP.13 Agent-To-Agent Trust Statements]

    SP01 --> SP02
    SP01 --> SP03
    SP01 --> SP04
    SP01 --> SP05
    SP01 --> SP13

    SP02 --> Roots[Local roots, keys, policies, patterns, tools, revocations]
    SP03 --> Attest[Request/result attestations]
    SP04 --> Decisions[Deterministic decisions and explanations]
    SP05 --> Evidence[Signed audit and release evidence]
    SP13 --> Peers[Signed agent cards and delegation-chain validation]

    Roots --> Runtime[Embedded runtime verification]
    Attest --> Runtime
    Decisions --> Runtime
    Evidence --> Runtime
    Peers --> Runtime

    Runtime --> SP14[SP.14 Ecosystem Integrations And Adoption]
    Runtime --> SP15[SP.15 Benchmark Methodology And Baselines]

    Legacy[Existing envelope and registry-named APIs] --> Migration[V3 migration guide and historical fixtures]
    Migration --> Runtime
```

### Planned Delivery Tracks

| Track | Goal | Spec |
|-------|------|------|
| Agent Trust Profile | Define the SigilGuard-owned profile, vocabulary, canonical statements, breaking boundary, and migration target. | [`SP.01`](specs/SP.01-sigilguard-trust-profile.md) |
| Embedded Trust Bundles | Replace registry-first vocabulary with signed local bundle load/verify/cache/quarantine APIs and no network core. | [`SP.02`](specs/SP.02-embedded-trust-bundles.md) |
| Agent/MCP Attestations | Bind actors, tools, schemas, inputs, outputs, audiences, resources, manifests, and decisions. | [`SP.03`](specs/SP.03-mcp-attestation-gateway.md) |
| Boundary Scanner And Policy | Expand staged scanning, lifecycle phases, sandbox identity, output contracts, and deterministic source-to-sink policy. | [`SP.04`](specs/SP.04-boundary-scanner-and-policy-kernel.md) |
| Audit And Release Provenance | Add OTel attributes, signed evidence, inclusion/consistency proofs, witness cosigning, audit exports, release SBOM, and provenance. | [`SP.05`](specs/SP.05-audit-and-release-provenance.md) |
| Agent-To-Agent Trust | Sign and verify agent cards, agent request/response statements, and delegation chains. | [`SP.13`](specs/SP.13-agent-to-agent-trust-statements.md) |
| Ecosystem Integrations And Adoption | Ship integration contracts, cheatsheets, livebooks, security posture artifacts, and the announcement plan. | [`SP.14`](specs/SP.14-ecosystem-integrations-and-adoption.md) |
| Benchmarks And Baselines | Define the benchmark scenario matrix, regression gates, comparison rules, and SLO ratification. | [`SP.15`](specs/SP.15-benchmark-methodology-and-baselines.md) |

## Spec Catalogue

| ID | Status | Purpose |
|----|--------|---------|
| [`SP.01`](specs/SP.01-sigilguard-trust-profile.md) | planned | Agent Trust Profile. |
| [`SP.02`](specs/SP.02-embedded-trust-bundles.md) | planned | Embedded trust bundles. |
| [`SP.03`](specs/SP.03-mcp-attestation-gateway.md) | planned | MCP/tool attestations and capability manifests. |
| [`SP.04`](specs/SP.04-boundary-scanner-and-policy-kernel.md) | planned | Boundary-aware scanner and policy kernel. |
| [`SP.05`](specs/SP.05-audit-and-release-provenance.md) | planned | Audit and release provenance. |
| [`SP.06`](specs/SP.06-envelope-and-native-backend-contracts.md) | implemented/transition | Envelope and native backend transition contracts. |
| [`SP.07`](specs/SP.07-runtime-gate-and-streaming-contracts.md) | implemented | Runtime gate and streaming contracts. |
| [`SP.08`](specs/SP.08-mcp-gateway-and-confirmation-contracts.md) | implemented | MCP gateway and confirmation contracts. |
| [`SP.09`](specs/SP.09-audit-chain-and-anchor-contracts.md) | implemented | Audit chain and anchor contracts. |
| [`SP.10`](specs/SP.10-vault-and-identity-contracts.md) | implemented | Vault and identity contracts. |
| [`SP.11`](specs/SP.11-repo-policy-kernel-contracts.md) | implemented | Repo policy kernel contracts. |
| [`SP.12`](specs/SP.12-legacy-remote-bundle-adapter-contracts.md) | planned/removal | Legacy remote-bundle removal plan. |
| [`SP.13`](specs/SP.13-agent-to-agent-trust-statements.md) | planned | Agent cards and agent-to-agent trust statements. |
| [`SP.14`](specs/SP.14-ecosystem-integrations-and-adoption.md) | planned | Ecosystem integrations and adoption artifacts. |
| [`SP.15`](specs/SP.15-benchmark-methodology-and-baselines.md) | planned | Benchmark methodology and baselines. |

## Documentation Tree

```mermaid
flowchart TD
    Docs[docs/]
    Docs --> Research[research/]
    Docs --> Specs[specs/]
    Docs --> Tasks[tasks/]
    Docs --> Templates[templates/]

    Research --> R01[R.01 Embedded Agent Trust Profile]
    Research --> R02[R.02 Attestation Envelope And Canonical Encoding]
    Research --> R03[R.03 Trust Bundle Role Model]
    Research --> R04[R.04 Audit Proofs, Witnessing, And Privacy]
    Research --> R05[R.05 Actor Identity, Delegation, And A2A]
    Research --> R06[R.06 Agentic Threat Model And Control Mapping]
    Research --> R07[R.07 Ecosystem, Dependencies, And Adoption]
    Specs --> Security[SP.01-SP.15]
    Tasks --> TaskList[sigil-tasks.md]
    Templates --> ResearchTemplate[research-base.md]
    Templates --> SpecTemplate[spec-base.md]
    Templates --> TaskTemplate[task-base.md]
```

## Non-Goals

- No public hosted registry dependency.
- No Rust or NIF backend path.
- No remote network trust in core decision paths by default.
- No direct integration with outside inspiration projects.
- No legacy SIGIL runtime adapter as the v3 product center.
- No ML model weights in core; adaptive detection stays an optional
  behaviour with a deterministic nil-path.
