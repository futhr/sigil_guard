---
sigil_guard:
  id: "R.05"
  topic: "Actor Identity, Delegation, And Agent-To-Agent Trust"
  category: research
  status: complete
  created: "2026-07-02"
  updated: "2026-07-02"
  decision: adopted
  tags:
    [
      "identity",
      "spiffe",
      "did",
      "delegation",
      "token-exchange",
      "oauth",
      "a2a",
      "agent-cards",
      "wimse"
    ]
---

# R.05 - Actor Identity, Delegation, And Agent-To-Agent Trust

## Executive Summary

SigilGuard v3 treats identity as material it binds and verifies, never as a
system it owns. This note records decision D2 as **adopted**: actor and
issuer strings are recommended to be SPIFFE-shaped URIs
(`spiffe://trust-domain/workload-identifier`), arbitrary opaque strings
remain fully accepted, `did:key` identifiers are optionally accepted because
they verify offline, delegation chains follow the RFC 8693 `act`-claim model
(carried as a flattened order-preserving list, not the nested object) and
are digest-bound but semantically opaque to the core, and OAuth 2.1
authorization at the MCP layer is host-owned with SigilGuard binding only
the resulting audience and resource strings.

The note also lays the identity groundwork for D7: the `agent_request` and
`agent_response` statement types bind peer agent identity, the delegation
chain, and payload digests, and A2A agent cards become first-class,
DSSE-signed capability-manifest analogs verified against bundle-declared
issuers (full treatment in SP.13). This closes R.01's second deferred item
and R.01 Open Question 3.

## Research Question

Which identity representations should an embedded, offline verifier accept,
recommend, cryptographically verify, and carry opaquely?

Five sub-questions:

1. What shape should recommended actor and issuer strings take inside
   signed statements under profile id `sigil_guard_agent_trust/v1`?
2. Which identity formats does the core verify with cryptography, and which
   does it carry as opaque claims?
3. What is the canonical representation of a delegation chain when one
   agent acts on behalf of another actor?
4. Where does MCP-layer OAuth authorization live relative to the library
   boundary?
5. What identity material do agent-to-agent statements bind, and how are
   agent cards trusted?

## Methodology

- Primary standards were read directly: the SPIFFE ID standard, SPIFFE
  concepts and federation material, RFC 8693 (token exchange), RFC 8707
  (resource indicators), RFC 9728 (protected resource metadata), the MCP
  2025-11-25 authorization specification, W3C DID Core 1.1, the did:key
  method specification, W3C VC Data Model 2.0, RFC 7515 (JWS), and the A2A
  protocol repository.
- Draft-stage material (the WIMSE architecture draft and the OAuth
  on-behalf-of-for-AI-agents draft) is classified watch-only and is never
  used as a normative dependency. Post-knowledge-cutoff status claims were
  re-verified on 2026-07-02 and are marked as accessed values.
- Internal evidence: `lib/sigil_guard/identity.ex` (behaviour plus
  trust-level ordering), `lib/sigil_guard/identity/binding.ex` (near-stub
  struct), and the reference-consumer inventory, including its identity
  mapper (a `SigilGuard.Identity` implementation) and its agent-card
  signer, both read in source.
- Conflict handling: standards-track RFCs and W3C Recommendations outrank
  Candidate Recommendations, which outrank Internet-Drafts; production
  consumer behavior outranks hypothetical requirements when deciding what
  the core must keep accepting.

## Context

The v2 identity surface is deliberately thin. `SigilGuard.Identity` is a
behaviour plus a monotonic trust-level utility (`:low < :medium < :high`);
`SigilGuard.Identity.Binding` is a near-stub struct with `provider`, `id`,
`trust_level`, and `bound_at`. Trust derivation is host-owned by design,
and that boundary is correct: SigilGuard must not own authentication.

The reference consumer (a production agent runtime that embeds SigilGuard,
reviewed in the adjacent-ecosystem inventory) shows what hosts actually
build on that seam. Its identity mapper implements the
`SigilGuard.Identity` behaviour, maps principal roles to trust levels
through a hand-rolled closed map, and emits identity strings shaped like
`host:operator:42`. Its agent-card signer signs and verifies A2A v1.0 agent
cards with Ed25519 JWS (RFC 7515), reusing SigilGuard's `Signer.Ed25519`
keypair rather than introducing a second key. That is production evidence
for two claims: agent identity plus card signing is a real embedded need,
and hosts hand-roll it when the library offers no first-class surface.

v3 raises the stakes. Attestations (SP.01) place `actor` and `issuer`
inside signed canonical bytes; trust bundles (SP.02) declare issuers; the
two new statement types `agent_request` and `agent_response` (D7) bind peer
agent identity; and SP.10 needs a normalization and config-driven
trust-mapping contract. Without one recorded identity decision, each of
those specs would invent its own ad hoc answer.

## Findings

### SPIFFE: Recommend The ID Format, Not The Infrastructure

The SPIFFE ID standard defines a workload identity URI:
`spiffe://trust-domain/workload-identifier`. The trust domain names the
trust root; the path identifies the workload within it. The grammar is
closed and small: lowercase scheme and trust-domain characters, restricted
path segments, no query, no fragment, bounded total length. SPIFFE binds
the ID into verifiable documents as X.509-SVIDs (ID in the SAN URI) or
JWT-SVIDs (ID in `sub` with a required audience), and federates across
trust domains by exchanging trust bundles through bundle endpoints.

The recommendation adopted here is precise: the ID format, not the SPIRE
infrastructure.

- **Stable URI semantics.** Parsing and comparing a SPIFFE ID is pure
  string work. An embedded verifier validates shape, extracts the trust
  domain, and pattern-matches paths with zero network access.
- **Trust-domain scoping.** The trust-domain component maps directly onto
  bundle-declared issuers: a SigilGuard trust bundle declares which trust
  domains and key ids it accepts, and pattern rules scope trust levels to
  shapes like `spiffe://prod.example.org/agents/*`.
- **Federation-compatible later.** SPIFFE federation is trust-bundle
  exchange, which is exactly SigilGuard's Layer 1 vocabulary. When hosts
  later want cross-domain agent trust, importing another domain's issuer
  keys into a bundle is the same mechanism with no new architecture.
- **No mandatory infrastructure.** SPIRE (server/agent attestation, node
  API, registration) is deployment infrastructure. An embedded library must
  work when none of that exists, so SPIFFE shape is a recommendation for
  strings, never a requirement for infrastructure.

### Identity Claims Are Opaque To The Core

The opacity principle is the load-bearing rule of D2. SigilGuard carries
identity claims opaquely: it never interprets claim semantics for trust
decisions beyond exact-match and pattern rules declared in the trust bundle
or host configuration. Concretely, the core:

- compares identity strings by exact bytes or by bundle/config-declared
  patterns (the SP.10 config-driven trust mapping: an ordered
  actor-pattern-to-trust-level map, the reference consumer's stated need);
- includes identity strings in digests, attestations, and audit evidence,
  subject to the R.04 privacy classes;
- derives trust only through the host-owned `Identity` behaviour or
  through bundle-declared issuer and pattern rules;
- never grants privilege by format. A SPIFFE-shaped string earns nothing by
  its shape alone; it must still match a declared rule.

Arbitrary non-SPIFFE strings remain accepted permanently: host principals
(`host:operator:42`), service accounts, email-shaped subjects, and
opaque session ids are all valid actor values. Normalization (SP.10)
validates shape only when a string claims a recognized scheme, returns
strings, and never creates atoms from external input (CLAUDE.md rule 7).

### DID And VC: Accept did:key Optionally, Reject Resolution-Bound Methods

W3C DID Core reached v1.1 Candidate Recommendation in March 2026 (accessed
2026-07-02). DID methods split cleanly along the one axis SigilGuard cares
about: whether resolving the identifier requires a network.

- **`did:key` is offline-verifiable.** The identifier embeds the public key
  as multibase-encoded multicodec bytes; the DID document derives
  deterministically from the identifier itself. No resolution network
  exists or is needed. v3 therefore optionally accepts `did:key` as an
  actor or issuer format, and MAY use the embedded key directly for
  signature verification when a bundle or host designates that issuer.
- **`did:web` and ledger-backed methods are rejected for core.** Both
  require resolution (HTTPS fetch or ledger access) to obtain key material,
  which violates the offline default (CLAUDE.md rules 4 and 8). Hosts may
  resolve them externally and hand SigilGuard the resulting keys.
- **VC 2.0 credentials stay opaque references.** The W3C VC Data Model 2.0
  is a Recommendation, but verifying credentials means proof suites, status
  lists, and issuer resolution. v3 carries credential references opaquely
  in `credential_refs`; the core never verifies them.

### Delegation Chains Take The RFC 8693 act-Claim Shape

RFC 8693 (OAuth 2.0 Token Exchange) §4.1 defines the `act` claim as a
NESTED JSON object: the current actor appears in the outermost `act`, and
each prior actor nests one level deeper inside it, producing an unambiguous,
ordered delegation history. It is the only standards-track representation of
multi-hop acting-on-behalf-of that is pure data - no protocol run is needed
to carry or compare it.

SigilGuard adopts the RFC 8693 delegation MODEL but carries it as a
flattened, order-preserving LIST, one entry per hop, each hop
`{actor, optional evidence reference}` - element 0 is the outermost `act`
(current actor), ascending indexes are earlier delegations (increasing RFC
8693 nesting depth). This flattened list is functionally equivalent to, but
not structurally conformant with, the RFC's nested `act` object; the list
form is chosen for compact digest binding and index-based comparison in
embedded verification. Two rules govern the core:

- **Digest-bound, order-preserving.** The chain participates in the
  attestation's digests, so reordering, inserting, or dropping a hop breaks
  verification.
- **Semantically opaque.** The core does not evaluate hop semantics.
  Maximum chain depth and trust-derivation-across-hops rules are SP.13
  policy, not core verification.

The OAuth on-behalf-of-for-AI-agents draft (a token-exchange profile for
agents acting for users, introducing a `requested_actor` parameter;
accessed 2026-07-02) is convergent evidence: the ecosystem is converging on
act-claim-based delegation for agents, so adopting the same model keeps
SigilGuard chains mappable to whatever tokens hosts eventually receive.

### MCP-Layer OAuth Authorization Is Host-Owned

The MCP 2025-11-25 authorization specification anchors HTTP transports in
OAuth 2.1 with PKCE, RFC 8707 resource indicators (RFC 8707 dates from 2020;
the MCP 2025-06 revision made its use mandatory), and RFC 9728
protected-resource metadata for authorization-server discovery. That entire flow - token acquisition,
audience validation at the resource server, refresh, introspection - is
explicitly host-owned. SigilGuard never performs OAuth flows.

What SigilGuard does instead is bind the results: the audience and resource
strings the host obtained become attestation fields (SP.03), so a token
minted for one MCP server cannot be silently replayed against another
without a digest mismatch. This is the offline equivalent of resource
indicators for stdio and local tools, and it is the confused-deputy control
in R.06's mapping.

### WIMSE Is Watch-Only

The IETF WIMSE working group (Workload Identity in Multi System
Environments) is standardizing workload identity across systems, but its
architecture document remains an Internet-Draft (draft-ietf-wimse-arch,
accessed 2026-07-02). WIMSE builds on SPIFFE-style workload identifiers, so
the SPIFFE-shaped recommendation adopted here already points at the same
vocabulary. Status: watch-only. When WIMSE RFCs land, align terminology in
a follow-up note; take no dependency now.

### A2A Agent Cards Are Capability Manifests For Agents

The A2A protocol describes agents through agent cards: JSON documents
carrying name, description, capabilities, skills, endpoints, security
schemes, and an optional array of JWS signatures. Functionally, an agent
card is to an agent what a capability manifest is to a tool: metadata that
steers a counterpart's behavior, and therefore supply-chain input, never
trusted context.

The reference consumer already treats cards this way. Its agent-card signer
builds the A2A v1.0 signing input (base64url of the card JSON with the
`signatures` member stripped), signs with Ed25519 through SigilGuard's
signer, and verifies inbound cards on discovery.

v3 gives agent cards first-class treatment (full spec in SP.13):

- **Digest-bound.** A card digest joins the manifest-digest family, so peer
  statements bind exactly which card was trusted.
- **DSSE-signed.** Cards are signed as DSSE envelopes with payloadType
  `application/vnd.sigilguard+json`, with a documented 1:1 mapping from
  the reference consumer's current JWS form so migration is mechanical.
- **Verified against bundle-declared issuers.** Card trust comes from the
  trust bundle, not from the transport that delivered the card. Unknown
  issuers quarantine.
- **Bound into the D7 statement types.** `agent_request` and
  `agent_response` bind peer identity, the delegation chain, and payload
  digests. The names are protocol-neutral; A2A and ACP specifics live in
  SP.13 predicates. The motivating threat class is OWASP ASI07 (inter-agent
  communication abuse), mapped in R.06.

## Comparative Analysis

| Criterion | Opaque strings only | SPIFFE-shaped recommended + opaque accepted (adopted) | DID-first | Full OAuth integration |
|-----------|---------------------|-------------------------------------------------------|-----------|------------------------|
| Offline capability | Total, but shapeless | Total: parse/compare offline; optional did:key stays offline | Only did:key is offline; other methods need resolution | Requires reachable authorization servers |
| Ecosystem alignment | None | SPIFFE practice, WIMSE direction, federation vocabulary | W3C-aligned but weak in workload/agent practice | Aligns with MCP HTTP but at the wrong layer for a library |
| Implementation burden | None | Small: shape validation, pattern matching, optional multicodec decode | JSON-LD, proof suites, resolution stack | OAuth client/RS machinery, flows, token storage |
| Host friction | None, but no interop guidance | None: hosts keep existing principals unchanged | High: forces DID tooling onto hosts | High: duplicates the host's auth system |
| Forward compatibility (WIMSE/federation) | Poor: nothing to scope or federate | Strong: trust-domain scoping maps to bundle federation and WIMSE vocabulary | Partial: portable ids without trust-domain scoping | Poor: tokens are deployment-bound, not portable evidence |

Opaque-only fails forward compatibility: with no recommended shape there is
nothing for bundles to scope, federate, or pattern-match against. DID-first
fails host friction and burden: the reference consumer's principals would
need wrapping for zero security gain. Full OAuth integration fails the
library boundary: it duplicates host auth and drags network flows into
core decision paths.
The adopted option keeps every existing consumer working and gives new
consumers a standard shape to grow into.

## Recommendation

**Decision:** adopted.

D2 is recorded as five components:

1. Actor and issuer strings are recommended to be SPIFFE-shaped URIs; shape
   validation applies only when a string claims the `spiffe://` scheme.
2. Arbitrary opaque identity strings remain accepted; all trust derivation
   flows through the host-owned `Identity` behaviour or bundle/config
   pattern rules. Claims are never interpreted beyond exact-match and
   pattern rules.
3. `did:key` is optionally accepted as an actor/issuer format because it is
   offline-verifiable; resolution-bound DID methods are rejected for core;
   VC material stays in opaque `credential_refs`.
4. Delegation chains follow the RFC 8693 act-claim model, carried as a
   flattened order-preserving list of `{actor, optional evidence ref}` hops
   (functionally equivalent to, not structurally conformant with, the RFC's
   nested `act` object), digest-bound order-preserving into attestations,
   semantically opaque to core; depth and cross-hop trust rules land in
   SP.13.
5. OAuth 2.1 / RFC 8707 / RFC 9728 authorization at the MCP layer is
   host-owned; SigilGuard binds audience and resource strings into
   attestations and never performs OAuth flows. WIMSE stays watch-only.

This closes R.01's second deferred item (DID/VC support remains claim
references, with did:key as the one offline-verifiable exception) and R.01
Open Question 3 (trust bundles start with plain issuer/key references;
VC-style credentials stay optional opaque refs).

**Rationale:** every alternative either weakens the offline guarantee,
duplicates host authentication, or leaves the profile shapeless. The
adopted combination costs little to implement (string validation, pattern
matching, one optional multicodec decode), keeps the reference consumer's
production code valid without changes, and aligns the profile with where
workload and agent identity standards are demonstrably heading: SPIFFE
shape today, WIMSE vocabulary and act-claim agent delegation next.

## Impact On SigilGuard

- **Modules affected:** `SigilGuard.Identity` (behaviour kept as-is),
  `SigilGuard.Identity.Binding` (fleshed out per SP.10), the future
  attestation/statement builder (actor, issuer, delegation-chain, audience,
  and resource fields per SP.01), the future `SigilGuard.AgentCard`
  (SP.13), and the MCP gateway binding path (SP.03).
- **Specs to create/update:** SP.01 (actor/issuer field definitions inside
  statements), SP.03 (audience/resource binding at the gateway), SP.10
  (identity normalization plus the config-driven trust-mapping contract),
  SP.13 (agent cards, peer statements, delegation-chain validation).
- **Migration needed:** none for the reference consumer's `Identity`
  implementation - the behaviour survives v3 unchanged (D17). Agent-card
  signing gains a documented 1:1 JWS-to-DSSE mapping in SP.13, adoptable
  on the consumer's own schedule.
- **Breaking changes:** none introduced by this note. The actor/issuer
  schema lands inside the v3 attestation format already governed by D1 and
  SP.01.

## Sources

- [SPIFFE ID Standard](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md)
- [SPIFFE Concepts](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/)
- [SPIFFE Federation Standard](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md)
- [RFC 8693 - OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [RFC 8707 - Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/info/rfc8707)
- [RFC 9728 - OAuth 2.0 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [RFC 7515 - JSON Web Signature](https://datatracker.ietf.org/doc/html/rfc7515)
- [MCP Authorization (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [W3C Decentralized Identifiers (DIDs) v1.1 - CR status accessed 2026-07-02](https://www.w3.org/TR/did-1.1/)
- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [The did:key Method](https://w3c-ccg.github.io/did-key-spec/)
- [A2A Protocol Repository (agent cards)](https://github.com/a2aproject/A2A)
- [IETF WIMSE Working Group (accessed 2026-07-02)](https://datatracker.ietf.org/wg/wimse/about/)
- [WIMSE Architecture Internet-Draft (accessed 2026-07-02)](https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/)
- [OAuth On-Behalf-Of Authorization for AI Agents Internet-Draft (accessed 2026-07-02)](https://datatracker.ietf.org/doc/draft-oauth-ai-agents-on-behalf-of/)
