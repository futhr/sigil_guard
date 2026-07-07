---
sigil_guard:
  id: "R.03"
  topic: "Trust Bundle Role Model"
  category: research
  status: complete
  created: "2026-07-02"
  updated: "2026-07-02"
  decision: adopted
  tags:
    [
      "trust-bundles",
      "tuf",
      "roles",
      "thresholds",
      "key-rotation",
      "revocation",
      "rollback-protection",
      "dsse"
    ]
---

# R.03 - Trust Bundle Role Model

## Executive Summary

SigilGuard v3 trust bundles adopt a TUF role-subset vocabulary: a root role
plus delegated signer roles, m-of-n signature thresholds, per-role expiry,
monotonic sequence numbers with persisted rollback floors, revocation by
explicit list and by omission from the next root document, and a documented
emergency rotation ceremony. The bundle document is signed as a DSSE
envelope over its JCS-canonical bytes, with DSSE's multi-signature array
carrying the threshold signatures. TUF's snapshot and timestamp roles are
rejected for the embedded case because they defend live repository serving,
which SigilGuard does not do. This note records decision D3 as adopted and
closes the docs-corpus gap on bundle-signer compromise and emergency
rotation. SP.02 is the consuming spec.

## Research Question

What role, threshold, and rotation model does an embedded, offline,
no-network trust bundle need?

Four sub-questions:

1. Which TUF mechanics transfer to a bundle that ships inside a host
   application's release artifact and is loaded atomically, and which
   mechanics exist only to defend live repository serving?
2. What survives the compromise of one signing key, and what is the
   documented recovery procedure when the compromise reaches root keys?
3. How do role thresholds map onto the DSSE envelope's multi-signature
   array without inventing a new signature container?
4. What stops an attacker from re-serving an old, validly signed bundle
   after a rotation (rollback and fork attacks)?

## Methodology

- Primary specification reading: the TUF specification (roles, thresholds,
  expiry, version and rollback rules, and the root-update chain walk in the
  client workflow), the TUF Augmentation Proposals (TAP 8 on key rotation
  and explicit self-revocation), the DSSE protocol document (PAE and
  multi-signature verification), and RFC 8785 (JCS).
- Operational practice: the Sigstore root-signing repository, which runs
  TUF root ceremonies in public with hardware-backed keys and a 3-of-5
  root threshold (repository state accessed 2026-07-02).
- Internal evidence: the v2 `SigilGuard.Registry.Bundle` implementation on
  the `native` branch (one optional Ed25519 provenance signature gated by
  `require_signature`), the SP.02 draft field sketch (sequence,
  delegations, rollback floor, signatures), and plan decision D3.
- Conflict handling: where TUF mechanics assume a live repository with
  independently fetched metadata files, the embedded single-document model
  was treated as the controlling constraint, and each mechanic was either
  re-derived for one atomically loaded document or rejected with recorded
  rationale.

## Context

The v2 model being replaced is `SigilGuard.Registry.Bundle`: one optional
Ed25519 signature inside a `provenance` block, verified over canonical
bundle bytes that exclude signature metadata. Unsigned bundles verify
unless the host sets `require_signature: true`. There are no roles, no
thresholds, no rotation chain, no revocation list, and rollback protection
exists only as a cache-level sequence comparison. A trust bundle carries
signed local trust material — keys, tool manifests, policy rules, scanner
patterns, revocations — so a single leaked signer key is a total
compromise: the attacker can forge every category of trust input, and
nothing in the v2 format supports recovery.

SP.02 (embedded trust bundles) is the consumer of this note. It turns the
adopted model into a normative data model, verification algorithm, error
taxonomy, and golden vectors. SP.12 removes the legacy remote registry
path whose naming the v2 modules carry. R.01 adopted local signed trust
bundles as Layer 1 of the Agent Trust Profile and named TUF as the pattern
source; this note fixes exactly which TUF mechanics are in and which are
out. Envelope and canonicalization decisions are owned by D1 (R.02); this
note reuses them without restating their rationale.

## Findings

### TUF Mechanics That Transfer To Embedded Bundles

Six TUF mechanics defend threats that exist regardless of how bundle bytes
reach the verifier. All six transfer.

**Roles.** TUF separates authority by role. For SigilGuard the subset is a
root role, which signs the role and key declarations themselves, and
delegated signer roles, which sign bundle documents. A bundle-signer key
never changes the key set; only a root threshold can do that. Compromising
a delegated signer therefore never yields the authority to launder the
compromise into the trust anchor.

**m-of-n signature thresholds.** Each role declares n authorized keys and
a threshold m. Role output is valid only when at least m distinct
authorized keys have produced valid signatures over it. Compromise of
k < m keys is survivable: the attacker cannot forge role output alone, and
the remaining keyholders retain enough quorum to sign the rotation that
evicts the compromised keys.

**Per-role expiry.** Every signed document carries an expiry, and a
verifier MUST reject expired material. Expiry bounds the useful lifetime
of stolen signatures and forces periodic re-signing, which keeps ceremony
practice alive. Root expiry is long because ceremonies are expensive;
signer-role expiry is shorter.

**Monotonic sequence numbers and rollback floors.** Each bundle carries a
monotonically increasing sequence number. Verifiers persist the highest
accepted sequence as a floor and MUST reject bundles whose sequence falls
below it, which stops an attacker from re-serving an old, validly signed
bundle whose keys or rules have since been rotated away. A rotated root
document additionally raises the floor explicitly, so even unexpired
pre-rotation bundles die at verification time. Exact comparison semantics
and the error atom are fixed in SP.02.

**Revocation by list and by omission.** Both mechanisms are required. An
explicit revocation entry kills a key immediately, mid-cycle, regardless
of any unexpired signatures it produced. Omission from the next root
document kills keys structurally: a key absent from the current key set
counts toward no threshold, so forgotten legacy keys cannot silently
retain authority. The list handles emergencies; omission guarantees the
steady state.

**Ceremony-based key management.** Root keys are generated and used only
in documented offline ceremonies with a quorum of keyholders present.
Sigstore's root-signing repository demonstrates the practice at production
scale: scripted public ceremonies, hardware tokens, five root keyholders
at a threshold of three, and every ceremony artifact committed for
independent verification (accessed 2026-07-02).

### Rejected: Snapshot And Timestamp Roles

TUF's snapshot and timestamp roles are rejected for the embedded case.

Both roles defend live repository serving. The snapshot role signs a
manifest of all other metadata files so a mirror cannot serve a
mix-and-match combination of individually valid files drawn from
different repository states. The timestamp role signs a short-lived
statement of the latest snapshot so a mirror cannot freeze a client on
stale metadata indefinitely. Both threats require an attacker who sits in
the serving channel and chooses which files a client sees, and both
defenses require frequent online re-signing.

An embedded SigilGuard host has neither the threat nor the tolerance for
the defense. The host controls its own update cadence: bundles arrive
through the host's release process, not through a mirror an attacker can
occupy. The bundle is one document loaded atomically; there are no
independently fetched metadata files to mix, so mix-and-match is
structurally impossible. An online timestamp role would also insert a
network dependency into the core verification path, which CLAUDE.md rule 8
and R.01's local-first decision forbid. Freshness in the embedded model is
bounded instead by per-role expiry plus the rollback floor: a stale bundle
either expires or falls below the floor of any host that has accepted a
newer one.

### Emergency Rotation Ceremony

This is the documented operational procedure for key compromise, up to and
including root keys. SP.02 turns it into acceptance criteria; hosts embed
it in incident runbooks. The steps are normative.

1. A quorum of the remaining root keyholders convenes. The root threshold
   m MUST be chosen so the expected worst-case compromise leaves at least
   m holders uncompromised (Sigstore: three of five).
2. New root keys are generated offline, during the ceremony, on hardware
   that never touches the network.
3. The new root document is cross-signed by the old root threshold AND by
   the new keys. This is TUF's root-chaining rule: verifiers accept root
   version N+1 only when it carries a threshold of signatures valid under
   root version N and a threshold valid under N+1 itself. The old quorum
   proves continuity; the new keys prove possession.
4. The sequence/rollback floor is bumped so that all prior bundles are
   invalidated, including bundles carrying unexpired signatures from the
   compromised keys.
5. Distribution happens through the host's normal release channel. There
   is no emergency side channel; adding one would create exactly the live
   serving path this model rejects.
6. Explicit revocation entries for the compromised keys take effect
   immediately regardless of role expiry, covering hosts that load the new
   root while older signer material is still circulating.

Verification rule: verifiers walk the rotation chain from their pinned
genesis root — genesis, then each cross-signed successor in order, then
the current bundle. A forked chain, meaning two distinct children of one
root version, MUST be rejected outright. A fork is evidence of key
compromise or issuer equivocation, and a verifier that silently picks a
branch appoints itself arbiter of a split it cannot adjudicate.

### DSSE Mapping For Bundle Signing

The bundle needs threshold signatures over canonical bytes. DSSE already
provides that container, and D1 (R.02) adopts DSSE for every other signed
SigilGuard artifact, so the bundle uses the same envelope rather than a
bespoke signature block.

- The bundle document is the DSSE payload. The payload bytes are the JCS
  (RFC 8785) canonicalization of the bundle document, base64url encoded
  without padding in the `payload` field.
- `payloadType` is `application/vnd.sigilguard+json`.
- Signatures are computed over PAE bytes, never over the raw payload:
  `"DSSEv1" SP len(type) SP type SP len(body) SP body`.
- The `signatures` array of `{keyid, sig}` entries carries the threshold
  signatures. The verifier resolves each `keyid` against the signing
  role's declared key set, verifies each signature (Ed25519 via OTP
  `:crypto`), counts distinct authorized keys with valid signatures, and
  requires at least the role's threshold m out of its n keys. Unknown
  keyids and duplicate keyids MUST NOT count toward the threshold.
- Bundle-state evidence — statements recording that a bundle was loaded,
  quarantined, rotated, or floor-bumped — uses the in-toto-style Statement
  shape (`_type: "https://in-toto.io/Statement/v1"`) with predicateType
  `https://sigilguard.dev/trust-bundle-state/v1`. The bundle document
  itself is not wrapped in a Statement; it is a first-class payload.

Adopted v1 posture: the schema always carries m and n, and the v1 runtime
MAY enforce threshold = 1. Every role declaration in every bundle states
its full key set and threshold, and golden vectors cover multi-signature
envelopes, but v1 verification is permitted to require a single valid
authorized signature. Raising enforcement to the declared m is a runtime
upgrade with no wire-format change; SP.02 records the enforcement default
and its error atom.

## Comparative Analysis

| Criterion | Single signature (v2 status quo) | TUF role subset (adopted) | Full TUF |
|-----------|----------------------------------|---------------------------|----------|
| Signer-compromise survivability | None: one leaked key forges any bundle, no recovery path | k < m key compromises survivable; documented ceremony recovers from root compromise | Same as subset |
| Rollback protection | Cache-level sequence compare only; nothing signed enforces a floor | Signed sequence plus persisted floor plus genesis-pinned rotation chain | Version checks plus snapshot/timestamp freshness |
| Rotation story | Undefined; re-keying is out-of-band trust-on-first-use | Cross-signed root chain, documented ceremony, dual revocation | Same chain plus frequent online snapshot/timestamp re-signing |
| Implementation size (pure Elixir) | Smallest; already exists | Moderate: roles, threshold counting, and chain walk over the shared DSSE/JCS code from D1 | Large: four-plus role types, consistent snapshots, repository and mirror workflow |
| Offline capability | Full | Full: verification is network-free | Degraded: timestamp role presumes an online freshness endpoint |

## Recommendation

**Decision:** adopted.

SigilGuard v3 trust bundles use the TUF role subset — root plus delegated
signer roles, m-of-n thresholds carried in the schema, per-role expiry,
sequence numbers with rollback floors, revocation by list and by omission,
and the emergency rotation ceremony above — signed as DSSE envelopes over
the JCS-canonical bundle document.

**Rationale:** the subset takes every TUF mechanic that defends signed
trust material at rest and drops the two roles that defend live repository
serving, an architecture R.01 already rejected. It closes the docs-corpus
gap on bundle-signer compromise and emergency rotation: v2 had no answer
to "a bundle signing key leaked," and the answer is now a numbered
procedure with a chain-walk verification rule. The single-signature status
quo fails the survivability criterion outright. Full TUF buys no
additional protection for an embedded verifier while adding online
re-signing obligations and several times the metadata surface.

Error naming is reconciled in SP.02. This note deliberately does not fix
atoms such as `:sequence_below_floor` versus the existing
`:rollback_detected`, or `:threshold_not_met` versus a signature-count
error; SP.02 picks the final set and records the mapping from the v2
atoms.

## Impact On SigilGuard

- Modules affected: future `SigilGuard.TrustBundle`,
  `SigilGuard.TrustBundle.Verify`, and `SigilGuard.TrustBundle.Cache`
  (rotation chain walk, threshold verification, floor persistence). The
  legacy `SigilGuard.Registry.Bundle` and `SigilGuard.Registry.Cache`
  modules are deleted per SP.12 rather than migrated.
- Specs to create/update: SP.02 (primary consumer: data model,
  verification algorithm, ceremony acceptance criteria, error taxonomy,
  golden vectors) and SP.12 (legacy registry removal and the removal map
  for the v2 bundle surface).
- Migration needed: yes. v2 single-signature bundles do not verify under
  v3. `MIGRATING-1.0.md` maps the v2 provenance block to a v3 role
  declaration plus DSSE envelope, and legacy bundle fixtures move to
  `test/fixtures/historical/`.
- Breaking changes: yes — the bundle format. Sequence semantics, signature
  container, key declaration, and revocation shape all change.

## Sources

- [The Update Framework Specification](https://theupdateframework.github.io/specification/latest/)
- [TUF Augmentation Proposals (TAPs)](https://github.com/theupdateframework/taps)
- [TAP 8 - Key rotation and explicit self-revocation](https://github.com/theupdateframework/taps/blob/master/tap8.md)
- [Sigstore root-signing ceremonies (accessed 2026-07-02)](https://github.com/sigstore/root-signing)
- [DSSE - Dead Simple Signing Envelope protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
- [RFC 8785 - JSON Canonicalization Scheme](https://www.rfc-editor.org/info/rfc8785)
- [in-toto Attestation Framework](https://github.com/in-toto/attestation)
