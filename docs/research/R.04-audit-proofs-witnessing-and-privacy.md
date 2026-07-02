---
sigil_guard:
  id: "R.04"
  topic: "Audit Proofs, Witnessing, And Privacy"
  category: research
  status: complete
  created: "2026-07-02"
  updated: "2026-07-02"
  decision: adopted
  tags:
    [
      "audit",
      "merkle-proofs",
      "transparency",
      "witnessing",
      "privacy",
      "gdpr",
      "scitt"
    ]
---

# R.04 - Audit Proofs, Witnessing, And Privacy

## Executive Summary

SigilGuard's audit chain is tamper-evident but not yet third-party verifiable:
proving anything about a checkpointed segment requires handing the verifier
every event in the segment, and a compromised operator can present forked
chains to different parties. This note records decision D10 as adopted: v3
extends the existing HMAC chain and Merkle checkpoints with simplified
RFC 9162-style inclusion and consistency proofs computed over the existing
domain-separated tree, optional third-party witness cosigning of checkpoint
statements via DSSE multi-signatures, a per-field privacy classification
vocabulary (`clear | hashed | redacted | omitted`), and a GDPR digest-first
stance in which erasure targets host-side payload stores while the chain holds
only digests. It also records decision D4: SCITT transparency receipts are
vocabulary alignment plus an optional post-GA adapter, never core. The
existing `"sigil-audit-leaf-v1:"` and `"sigil-audit-node-v1:"` prefixes are
retained, and the existing tree shape is proof-compatible with RFC 9162
without re-issuing any checkpoint.

## Research Question

What minimal verifiable-log constructs does an embedded audit chain need so
that its evidence is third-party verifiable and privacy preserving, without
turning the library into a networked transparency service?

Four sub-questions:

1. Which RFC 9162 mechanics apply to the existing Merkle checkpoint
   implementation, and which belong to log-serving infrastructure that an
   embedded library must not adopt?
2. How does an offline-first library defend against split-view attacks, where
   the checkpoint signer shows different chains to different verifiers?
3. What privacy rules must govern audit event fields so that evidence remains
   exportable and anchorable under GDPR, including the right to erasure?
4. Do SCITT transparency receipts belong in core, in an adapter, or nowhere?

## Methodology

- Primary specifications were read directly: RFC 9162 (Certificate
  Transparency v2), RFC 6962 (historical CT v1), RFC 9943 (SCITT
  architecture), the DSSE envelope specification, and the C2SP
  tlog-checkpoint, tlog-cosignature, and tlog-tiles specifications.
- The transparency.dev witness ecosystem and Trillian Tessera were reviewed
  as the current production pattern for checkpoint cosigning and for
  tile-based log storage at scale.
- GDPR Article 17, Recital 26, the Article 29 Working Party opinion on
  anonymisation techniques, and NIST SP 800-88r1 (cryptographic erase) were
  used for the privacy analysis.
- The current implementation was read at the source level:
  `lib/sigil_guard/audit.ex`, `lib/sigil_guard/audit/checkpoint.ex`,
  `lib/sigil_guard/audit/export.ex`, and the anchor modules.
- The claim that the existing promotion-based tree matches the RFC 9162 tree
  shape was verified computationally during authoring: for every size
  n = 1..256, the promotion construction and the RFC 9162 recursive
  split-at-largest-power-of-two construction produce identical roots under
  SigilGuard's prefixes. SP.05 pins this equivalence with golden vectors.
- RFC 9943, the Tessera repository, and the transparency.dev article URLs
  postdate the model knowledge cutoff and were re-verified on 2026-07-02.

## Context

The v0.2.x audit subsystem already implements a layered evidence model:

- **HMAC chain** (`SigilGuard.Audit`): each event is linked with HMAC-SHA256
  over its canonical bytes. The first event uses the genesis marker:
  `HMAC(key, canonical_bytes(event) <> "genesis")`; every subsequent event
  uses `HMAC(key, canonical_bytes(event) <> prev_hmac)`. Segments verify
  against a stored tip via a `:prev_hmac` anchor.
- **Merkle checkpoint** (`SigilGuard.Audit.Checkpoint`): an ordered SHA-256
  Merkle tree over event HMACs only, never raw event bodies. Leaf hash is
  `SHA-256("sigil-audit-leaf-v1:" || event_hmac)`; interior node hash is
  `SHA-256("sigil-audit-node-v1:" || left || right)`; the empty tree hashes
  `"sigil-audit-empty-v1"`. Odd nodes are promoted to the next level rather
  than duplicated. The checkpoint record (kind
  `sigil_guard.audit.checkpoint`, version 1, algorithm `sha256-merkle-v1`)
  carries `merkle_root`, `event_count`, `generated_at`, plus chain-linkage
  fields (`prev_hmac`, first/last event ids and HMACs) and optional metadata
  and anchor details. Checkpoints are Ed25519-signed over canonical bytes
  with the signature excluded from the signed material.
- **Anchors and exports**: `SigilGuard.Audit.Anchor` with a store behaviour
  (LocalFile and HTTP implementations) and `Anchor.Receipt`;
  `SigilGuard.Audit.Export` packages a checkpoint with optional Ed25519
  provenance and an optional anchor record for append-only or WORM storage
  while raw events stay local.

The known gap is verifiability, not integrity. Chain truncation is detectable
only by comparing against a stored checkpoint or anchored tip. Worse,
`Checkpoint.verify/3` requires the complete event segment to recompute the
root, so a third party cannot check that one event is covered by a checkpoint
(inclusion) or that a newer checkpoint extends an older one (consistency)
without receiving every event. And every checkpoint carries exactly one
signature from the operator who also runs the chain, so a compromised
operator can sign two divergent chains and show each verifier a consistent
lie. These are the classic transparency-log problems, and RFC 9162 solved
them a decade ago with O(log n) proofs and independent witnesses.

## Findings

### RFC 9162 Proof Mechanics Map Directly Onto The Existing Tree

RFC 9162 defines the Merkle Tree Hash with one-byte domain separation: a leaf
hashes as `H(0x00 || data)` and an interior node as
`H(0x01 || left || right)`. The separation defeats second-preimage attacks
that splice interior nodes into leaf positions (the vulnerability class
behind CVE-2012-2459 in Bitcoin's unseparated tree). SigilGuard already has
the equivalent construction with string prefixes instead of single bytes:
`"sigil-audit-leaf-v1:"` in place of `0x00` and `"sigil-audit-node-v1:"` in
place of `0x01`. The string prefixes MUST be retained: changing them would
invalidate the root of every already-issued checkpoint, and they additionally
namespace the hash inputs against cross-protocol collisions, which one-byte
prefixes do not.

Three deltas from RFC 9162 exist and are all deliberate:

1. Prefixes are versioned strings, not `0x00`/`0x01` bytes (compatibility
   with issued checkpoints).
2. Leaves are event HMACs, not raw entries (privacy; see below).
3. The empty tree hashes the string `"sigil-audit-empty-v1"` rather than the
   empty string (explicit domain separation for the degenerate case).

The tree shape itself needs no delta. The existing implementation builds the
tree level by level, pairing left to right and promoting an unpaired last
node upward. RFC 9162 instead defines the root recursively, splitting n
leaves at k, the largest power of two smaller than n. These constructions
produce the same tree for every size: pairing blocks at level L are aligned
to multiples of 2^L, and every RFC subtree boundary is such a multiple, so no
pair ever crosses a boundary. The computational check described in
Methodology confirmed identical roots for all sizes 1..256. Consequence: the
RFC 9162 proof algorithms apply to already-issued checkpoints unchanged, with
no re-rooting and no checkpoint re-issuance.

The two proof constructs v3 adopts:

- **Inclusion proof** (RFC 9162 section 2.1.3): a leaf index plus an audit
  path of sibling hashes, one per level, at most ceil(log2(n)) hashes. The
  verifier recomputes the root bottom-up from the domain-separated leaf hash
  and the path, then compares against the root in a trusted checkpoint. A
  match proves the event's HMAC is covered by that checkpoint.
- **Consistency proof** (RFC 9162 section 2.1.4): a node set of O(log n)
  hashes proving that the tree at size n1 is a prefix of the tree at size
  n2. Both the old root and the new root recompute from the set. This is the
  truncation and fork detector: an operator cannot drop or rewrite
  checkpointed events and still produce a valid consistency proof between
  the old and new checkpoints.

A SigilGuard checkpoint is already the RFC 9162 "signed tree head" in local
form: a signed `(merkle_root, event_count, generated_at)` tuple plus
chain-linkage fields. Nothing about the record must change for proofs to
verify against it.

The simplification boundary is explicit: SigilGuard implements the proof
algorithms over its existing tree and nothing else from CT v2. There is no
gossip protocol, no HTTP log-serving API, no signed certificate timestamps,
no maximum merge delay, and no monitor infrastructure. Proof generation is a
library function evaluated by the host that holds the events; proof
verification is a pure function over `(proof, leaf, checkpoint)`. SP.05 owns
the algorithms, JSON shapes, verification pseudo-code, error atoms, and a
small-tree golden vector.

Because leaves are HMAC outputs under the chain key, an inclusion proof
reveals only the event's HMAC and unrelated sibling hashes. Event bodies,
digests, and metadata never leave the host. Proofs are therefore safe to
attach to exports and anchors by construction.

### Witness Cosigning Closes The Split-View Gap Without A Network

A single-signer checkpoint proves nothing against its own signer. The
transparency ecosystem's answer is checkpoint cosigning: independent
witnesses verify a new checkpoint's signature and its consistency proof from
the last checkpoint they cosigned, then add their own signature. The
transparency.dev witness implementations and the C2SP tlog-checkpoint and
tlog-cosignature specifications standardize this pattern for note-formatted
checkpoints; Sigstore and the Go module sum database run it in production.

SigilGuard adopts the pattern, not the wire format. Signed checkpoint exports
in v3 are DSSE envelopes (decision D1, R.02) with payloadType
`application/vnd.sigilguard+json` over a JCS (RFC 8785) canonical checkpoint
statement. DSSE carries a `signatures` array of `{keyid, sig}` entries over
identical PAE bytes, so witness cosigning is native to the envelope: a
witness appends one entry and never modifies the payload. Verification is
threshold-based, reusing the m-of-n vocabulary from the trust-bundle role
model (D3, R.03): a policy states how many signatures from a named witness
key set a checkpoint needs before it counts as witnessed. The 0.2.x embedded
single-signature checkpoint format remains valid and verifiable; DSSE
wrapping applies to exports and cosigning, not to local storage.

Witnessing is optional and offline-compatible. A witness is any second party
holding its own Ed25519 key: a second key owned by the host operator's
security team, an organizational auditor, or an external service. The witness
MUST verify the consistency proof from its previously cosigned checkpoint
before signing; that check is what makes a cosignature mean "I saw the same
chain." Transport between host and witness is host-owned; an air-gapped
witness fed export packages satisfies the model. Core ships the cosigning and
threshold-verification primitives only.

Tile-based storage (Trillian Tessera, the C2SP tlog-tiles layout) was
evaluated and rejected for v3. Tiles optimize serving Merkle tree reads as
cacheable static resources for logs with millions of entries and public read
traffic. Embedded audit logs are small, are not publicly served, and export
at checkpoint granularity, so tiles solve a problem SigilGuard does not have.
Tiles remain the documented future-scale option: they are a storage layout
over the same tree, so nothing adopted here forecloses them. Byte-level
interoperability with generic tlog tooling would additionally require
migrating the string prefixes to `0x00`/`0x01`, which is a deliberate
non-goal.

### Privacy Classes And A Digest-First GDPR Stance

Every audit event field MUST carry exactly one classification from a closed
vocabulary:

| Class | Meaning |
|-------|---------|
| `clear` | Stored verbatim: verdicts, event types, timestamps, rule ids. |
| `hashed` | Only a salted or HMAC-keyed digest is stored. |
| `redacted` | A fixed placeholder is stored to preserve record structure. |
| `omitted` | The field never enters the event. |

The normative per-field tables over the signed audit event land in SP.05;
SP.09 records the constants. The classification applies uniformly to the
chain, to OpenTelemetry attributes, and to CloudEvents projections: a field
classified `hashed` in the chain MUST NOT appear `clear` in telemetry.

The digest-first principle already practiced by the implementation becomes
normative: raw payloads never enter the chain. Events carry action, payload,
and context digests, classifications, and decision metadata. Checkpoints
digest event HMACs, not bodies; exports package checkpoints, not events.

GDPR analysis:

- **Right to erasure (Article 17)** targets the host-side payload and
  quarantine stores where raw personal data actually lives. The chain holds
  digests and decision metadata, so erasing source material does not touch
  chain integrity: HMACs and Merkle roots are computed over canonical event
  bytes, which are unchanged by deleting the payloads those digests point
  to. The perceived conflict between immutable logs and erasure is resolved
  by construction, not by exception handling.
- **Hashed personal data may still be personal data.** GDPR Recital 26 and
  the Article 29 Working Party opinion on anonymisation establish that
  pseudonymised data attributable to a person via additional information
  remains personal data; a bare SHA-256 of an email address falls to a
  dictionary. Two consequences: high-sensitivity fields use `omitted`,
  because the safest digest is no digest; identity-bearing fields that must
  stay correlatable use salted or HMAC-keyed hashing under a per-deployment
  field-hash key.
- **Key destruction is cryptographic erasure** (NIST SP 800-88r1).
  Destroying the field-hash key severs the link between stored digests and
  persons while leaving the digest bytes, and therefore the chain HMACs and
  Merkle roots, byte-identical and verifiable. The field-hash key MUST be a
  separate key from the chain HMAC key so that crypto-erasure of identity
  linkage never degrades chain verifiability.

### SCITT: Vocabulary Alignment Now, Adapter Later, Never Core

RFC 9943 (the SCITT architecture, published June 2026) defines transparency
services that register COSE-signed statements under a registration policy and
return receipts: cryptographic proof that a statement was accepted into an
append-only log at a point in time. For SigilGuard evidence, a receipt would
add independent, timestamped registration of checkpoints, which is stronger
than self-signed checkpoints plus witnesses for cross-organization disputes.

A SCITT dependency is rejected for core on two grounds. First, registration
is a networked round-trip to a transparency service; SigilGuard core is
offline by default and adds no remote calls to decision or audit paths
(CLAUDE.md rules 4 and 8, R.01 constraint 1). Second, SCITT is COSE-based,
and core standardizes on DSSE over JCS (D1); carrying a second envelope stack
for an optional capability is unjustified.

The adopted posture (D4) is alignment without dependency. Checkpoint fields
(root, size, timestamp, issuer) map cleanly onto a SCITT signed statement
about an artifact, and `Anchor.Receipt` is kept semantically compatible with
receipt vocabulary. A post-GA adapter package can therefore submit exported
checkpoints to a SCITT transparency service and store returned receipts as
anchor metadata with zero core changes. This closes the third Deferred item
in R.01 ("whether SCITT transparency receipts belong in core or an optional
adapter"): optional adapter, post-GA, never core.

## Comparative Analysis

| Criterion | Status quo: HMAC chain + signed checkpoint | Proofs + witnessing (adopted) | Full CT v2 log | SCITT service |
|-----------|--------------------------------------------|-------------------------------|----------------|---------------|
| Truncation detection | Only against a stored checkpoint/anchor, with the full segment in hand | Consistency proofs, O(log n), verifiable by any checkpoint holder | Yes, plus gossip/monitors | Delegated to the service |
| Third-party verifiability | Verifier needs every event and must trust the sole signer | Inclusion/consistency proofs plus m-of-n witness threshold | Full public auditability | Independent receipts |
| Offline capability | Full | Full; witnesses may be air-gapped, transport host-owned | None; HTTP log serving is the product | None; registration is a network round-trip |
| Implementation size | Shipped | Pure proof functions + DSSE cosigning, roughly two small modules plus vectors | Log server, storage, APIs, monitor ecosystem | COSE stack + client + external service |
| Privacy posture | Digest-first chain, but verification hands all event bodies to the verifier | Proofs expose HMAC leaves and sibling hashes only; privacy classes normative | Log contents public by design | Statements leave the trust boundary |

## Recommendation

**Decision:** adopted.

**Rationale:** the adopted column dominates. Five components:

1. Implement RFC 9162-style inclusion and consistency proofs over the
   existing tree, retaining the `"sigil-audit-leaf-v1:"` and
   `"sigil-audit-node-v1:"` domain-separation prefixes and the
   `"sigil-audit-empty-v1"` empty-root input so every already-issued
   checkpoint root remains a valid proof target. Only the proof algorithms
   are adopted; CT v2 log-serving machinery is out of scope.
2. Add optional witness cosigning of checkpoint statements via the DSSE
   multi-signature array (payloadType `application/vnd.sigilguard+json`,
   JCS-canonical payloads), verified against m-of-n witness key thresholds.
   Witness transport is host-owned; single-signature checkpoints stay valid.
3. Make the `clear | hashed | redacted | omitted` per-field classification
   normative across chain, telemetry, and export surfaces (tables in SP.05).
4. Adopt the GDPR digest-first stance: erasure targets host-side payload and
   quarantine stores; identity-bearing fields hash under a dedicated
   field-hash key whose destruction is crypto-erasure; high-sensitivity
   fields are omitted outright.
5. Record D4: SCITT is vocabulary alignment plus an optional post-GA
   adapter, never core. R.01's third Deferred item is resolved.

Tile-based storage is rejected for v3 and parked as the future-scale option.

## Impact On SigilGuard

- Modules affected: `SigilGuard.Audit` (read/query API per SP.05),
  `SigilGuard.Audit.Checkpoint` (proof generation and verification helpers
  over the existing tree), `SigilGuard.Audit.Export` (proofs and witness
  signatures in export packages), `SigilGuard.Audit.Anchor` and
  `SigilGuard.Audit.Anchor.Receipt` (SCITT-compatible receipt vocabulary),
  plus a new proof module in the audit namespace defined in SP.05.
- Specs to create/update: SP.05 (primary: proof algorithms, JSON shapes,
  verification pseudo-code, golden vectors, witness cosigning, per-field
  privacy tables, read/query API); SP.09 (normative constants: leaf/node
  prefixes, empty-root input, genesis marker, canonical event bytes).
- Migration needed: none. Existing checkpoints verify unchanged, and proofs
  target already-issued roots.
- Breaking changes: no. Every addition is additive to the audit surface.

## Sources

- [RFC 9162 - Certificate Transparency Version 2.0](https://datatracker.ietf.org/doc/html/rfc9162)
- [RFC 6962 - Certificate Transparency (historical)](https://datatracker.ietf.org/doc/html/rfc6962)
- [RFC 9943 - SCITT Architecture](https://datatracker.ietf.org/doc/rfc9943/)
  (published June 2026; accessed 2026-07-02)
- [IETF SCITT Working Group](https://datatracker.ietf.org/wg/scitt/about/)
- [DSSE - Dead Simple Signing Envelope](https://github.com/secure-systems-lab/dsse)
- [RFC 8785 - JSON Canonicalization Scheme](https://www.rfc-editor.org/info/rfc8785)
- [C2SP tlog-checkpoint specification](https://c2sp.org/tlog-checkpoint)
- [C2SP tlog-cosignature specification](https://c2sp.org/tlog-cosignature)
- [C2SP tlog-tiles specification](https://c2sp.org/tlog-tiles)
- [transparency.dev witness implementation](https://github.com/transparency-dev/witness)
- [transparency.dev: Tile-Based Logs](https://transparency.dev/articles/tile-based-logs/)
  (accessed 2026-07-02)
- [Trillian Tessera](https://github.com/transparency-dev/tessera)
  (accessed 2026-07-02)
- [Transparent Logs for Skeptical Clients](https://research.swtch.com/tlog)
- [GDPR Article 17 - Right to erasure](https://gdpr-info.eu/art-17-gdpr/)
- [GDPR Recital 26 - Not applicable to anonymous data](https://gdpr-info.eu/recitals/no-26/)
- [Article 29 WP Opinion 05/2014 on Anonymisation Techniques](https://ec.europa.eu/justice/article-29/documentation/opinion-recommendation/files/2014/wp216_en.pdf)
- [NIST SP 800-88 Rev. 1 - Guidelines for Media Sanitization](https://csrc.nist.gov/pubs/sp/800/88/r1/final)
