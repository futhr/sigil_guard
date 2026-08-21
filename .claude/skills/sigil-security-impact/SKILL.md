---
name: sigil-security-impact
description: "Apply automatically when SigilGuard changes a public API, Agent Trust profile, bundle, attestation, AgentCard, boundary decision, scanner, runtime gate, MCP gateway, confirmation, audit, vault, policy, digest, key lifecycle, or v3 compatibility surface. Trace every security boundary phase."
---

# SigilGuard security impact

Map phase, origin, sink, actor/identity, trust zone, action digest, payload digest, policy verdict,
bundle/key identity and lifetime, replay/expiry, audit, host callback, and public v3 compatibility.
Core remains native Elixir, embedded/local, and network-free; only the host-provided audit anchor HTTP
behavior may perform sanctioned HTTP.

Trace callers, structs/types/specs, migration guide, docs, package contents, and the reference
consumer only through generic public contracts. Never write the private consumer's name or modules.

Require negative/tamper/replay/expiration/malformed tests and report unavailable host proof.
