---
sigil_guard:
  id: "R.08"
  topic: "MCP v2 (2026-07-28) And MCP Apps Security"
  category: research
  status: complete
  created: "2026-07-31"
  updated: "2026-07-31"
  decision: adopted
  tags:
    [
      "mcp",
      "mcp-2026-07-28",
      "mrtr",
      "mcp-apps",
      "confirmation",
      "capability-manifest",
      "json-rpc"
    ]
---

# R.08 - MCP v2 (`2026-07-28`) And MCP Apps Security

## Executive Summary

MCP v2 (`2026-07-28`) is a material wire and trust-boundary change: it removes
protocol sessions and initialization, adds per-request version metadata,
multi-round-trip requests (MRTR), required result discriminators, a reserved
JSON-RPC error range, cache metadata, parameter-to-header annotations, and an
official extension model. SigilGuard should adopt the revision through
transport-neutral canonical action binding, protocol-aware response shaping,
expanded capability manifests, and MCP Apps boundary helpers; it should not
become an MCP transport or depend on a TypeScript framework.

## Research Question

Which parts of MCP `2026-07-28`, MCP Apps, and the mcp-use v2 launch affect
SigilGuard's embedded security contracts, and which remain host-owned?

## Methodology

The final MCP specification, changelog, tools and discovery chapters, MCP Apps
extension specification, upstream mcp-use beta source, benchmark methodology,
and release-event transcript were compared with SigilGuard's gateway,
confirmation, manifest, context, threat-model, and integration code. Normative
MCP requirements take precedence over framework behavior and demonstrations.

## Context

SigilGuard 1.0 is unreleased and deliberately breaking. Its MCP gateway is
transport-neutral, but its pre-release confirmation projection retains only
string values, its custom error codes now occupy an MCP-reserved range, and its
manifest does not bind newer user-visible or MCP Apps metadata. This is the
lowest-cost point to correct those contracts.

## Findings

### MCP `2026-07-28`

- Protocol sessions, `Mcp-Session-Id`, `initialize`, and stream resumability
  are removed. Each request carries protocol version and client capabilities in
  `_meta`; `server/discover` is mandatory for servers but optional for clients.
- All successful results carry `resultType`; MRTR returns
  `resultType: "input_required"` plus `inputRequests` and optional
  `requestState`. The retry uses a new JSON-RPC id and carries
  `inputResponses` and `requestState`.
- `subscriptions/listen` owns list-change delivery. Tool lists may vary by
  per-request authorization, not by connection state.
- JSON-RPC server errors `-32000..-32019` are a legacy allocation where new
  codes should not be added; `-32020..-32099` are reserved by MCP. New local
  application codes should sit outside the `-32768..-32000` reserved band.
- The final revision assigns `-32020` to header/body mismatches, `-32021` to a
  required capability absent from client declarations, and `-32022` to an
  unsupported protocol revision. Missing required request metadata is ordinary
  invalid params (`-32602`).
- `tools/list` adds cache hints, deterministic ordering, `title`, `icons`, full
  JSON Schema 2020-12 support, and `x-mcp-header`. Sensitive values should not
  be exposed through headers.

### MCP Apps

The official `io.modelcontextprotocol/ui` extension adds `ui://` resources,
tool visibility for model/app callers, iframe-host JSON-RPC, declared CSP
domains, and permission requests. The host owns rendering and browser
sandboxing. SigilGuard can still verify resource bytes and metadata, enforce
same-server visibility, classify app-origin calls, and audit the boundary
without implementing a renderer.

The stable Apps document predates the final v2 revision and illustrates the
older initialization capability exchange. A v2 host must map extension support
into per-request client capabilities and discovery. This does not change
SigilGuard's transport-neutral boundary: the library consumes normalized
origin, server, visibility, and resource metadata after negotiation.

### Framework Evidence

mcp-use v2 demonstrates stateless TypeScript servers, MCP Apps, Inspector
tooling, and experimental view tools. Its performance results are framework
benchmarks, not evidence for adding a runtime dependency to a native Elixir
security library. The release demo's cross-tool workflows and explicit
permission before disclosing attendee allergy data support SigilGuard's
confirmation and source-to-sink model, while its experimental view tools are
not a stable contract to implement.

### SigilGuard Audit

The current gateway reduces requests and results to `tool`, `action`, and a
newline-joined sequence of string values. Map keys, numbers, booleans, and null
are absent from the confirmation digest input. Structurally different actions
can therefore share an approval digest. MCP MRTR expands this risk because
`inputResponses` and `requestState` participate in authorization and consent.

The current `-32050..-32056` registry conflicts with the final MCP allocation.
Sanitized results also omit `resultType`, and manifest translation ignores
`title`, `icons`, and `_meta.ui`.

## Comparative Analysis

| Criterion | Adopt mcp-use | Implement an MCP transport | Extend embedded contracts |
|-----------|---------------|----------------------------|---------------------------|
| Security fit | Indirect; framework-owned | Mixes transport and policy ownership | Direct boundary controls |
| Elixir fit | Poor | Possible but out of scope | Native and dependency-free |
| Compatibility | TypeScript beta coupling | Host adapter conflict | Protocol-aware host seam |
| Operational fit | Adds Node runtime | Adds network/session ownership | Preserves local-first design |
| Decision | rejected | rejected | adopted |

## Recommendation

**Decision:** adopted.

Supersede D19 with a legal application-defined error allocation outside
JSON-RPC's reserved server-error band; replace
the lossy confirmation projection with a canonical structured MCP action;
version the manifest to cover display, header, and Apps metadata; support
modern result discrimination and MRTR; add app-origin and UI-resource
verification; and update threat/integration documentation. Keep discovery,
HTTP headers, authorization, subscription transports, task storage, and iframe
sandboxing host-owned.

Treat only the exact final revision as supported. Future date versions may
change semantics and must not inherit v2 behavior until reviewed. Preserve
behavior-changing client capabilities and extension metadata in approval
bindings, while excluding correlation, logging, progress, and trace metadata.

## Impact On SigilGuard

- Modules affected: `SigilGuard.MCP.Gateway`, `SigilGuard.MCP.Protocol`,
  `SigilGuard.MCP.SecurityPayload`, `SigilGuard.MCP.AppResource`,
  `SigilGuard.ToolGateway`, `SigilGuard.ToolGateway.Base`,
  `SigilGuard.CapabilityManifest`, `SigilGuard.Context`, and tests.
- Specs to create/update: new `SP.16`; updates to `SP.03`, `SP.08`, and
  `SP.14`.
- Migration needed: JSON-RPC code mapping, confirmation digest/vector change,
  capability-manifest v2, and modern adapter options.
- Breaking changes: intentional and folded into the unreleased 1.0 line.

## Sources

- [MCP 2026-07-28 key changes](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
- [MCP versioning and compatibility](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)
- [MCP tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [MCP discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover)
- [MCP transports](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports)
- [MCP Apps specification](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)
- [mcp-use v2](https://github.com/mcp-use/mcp-use)
- [mcp-use v2 benchmark methodology](https://github.com/mcp-use/mcp-use/blob/main/benchmark.md)
- [MCP v2 release event](https://www.youtube.com/watch?v=W9XtugrmHts)
