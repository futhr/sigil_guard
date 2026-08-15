---
sigil_guard:
  id: "R.10"
  topic: "External Assessment Formats And Evidence Projection"
  category: research
  status: complete
  created: "2026-08-15"
  updated: "2026-08-15"
  decision: adopted
  tags:
    ["oscal", "scitt", "rfc9943", "rfc9942", "rfc9162", "dsse",
     "in-toto", "audit", "evidence", "assessment", "offline-verification"]
---

# R.10 - External Assessment Formats And Evidence Projection

## Executive Summary

OSCAL Assessment Results v1.2.3 can represent observations and reference a
hashed evidence resource, but its core model does not sign an assessment
document or authorize a producer to infer control satisfaction. SigilGuard
will therefore keep its existing audit evidence authoritative and offer a
separate, host-context projection containing observations only. The adapter
MUST NOT create findings, risks, or `satisfied` / `not-satisfied` conclusions.

**Decision: adopted.** The narrowly adopted design is specified by `SP.17`.
It does not change `Audit.Export`, the Agent Trust Statement registry, or any
decision-path behavior.

## Research Question

What may an embedded guard safely project into OSCAL Assessment Results for an
external assessment process, without claiming assessor authority, changing the
authoritative evidence bytes, or adding a network dependency?

## Methodology

The review was performed on 2026-08-15 against these pinned or dated sources:

1. The fourteen OSCAL metaschema files at tag `v1.2.3`, commit
   `e061961c7702afeabffdf5e59894d35e748dade1`, plus the release's generated
   Assessment Results JSON Schema.
2. OSCAL issue records 245, 345, and 841 as design history. Issue records do
   not override the released metaschema.
3. RFC 9943, RFC 9942, and RFC 9162 for transparency and receipt properties.
4. The compliance-trestle v4.2.0 and v5.0.0 signing designs, Evidentia, the
   in-toto predicate registry, and the still-open Baseline predicate proposal.
5. SigilGuard's emitted audit, export, checkpoint, evidence-reference,
   Statement, envelope, and trust-profile shapes at this repository revision.

Schema statements below were checked against exact field definitions,
cardinalities, closed enumerations, and `additionalProperties` rules. Searches
for signing constructs used exact element and field names; issue searches were
used only to explain why a construct is absent. Implementation claims were
checked against tagged source or published project documentation.

This note does not evaluate whether continuous monitoring improves security
outcomes. That is a different empirical question and is not needed to decide
whether a representation adapter is semantically safe.

Facts, inferences, and recommendations are labelled where the distinction is
security-relevant.

## Context

SigilGuard already produces HMAC-linked audit events, Merkle checkpoints,
optional checkpoint signatures, inclusion and consistency proofs, anchors,
and DSSE Agent Trust attestations. These artifacts remain local and verifiable
without placing HTTP on the decision path.

External assessment tooling consumes assessment artifacts rather than
SigilGuard's native records. The interoperability gap is real, but a format
conversion must not turn product behavior or a boundary verdict into a claim
that a deployed system satisfies a control objective.

## Findings

### OSCAL Assessment Results v1.2.3

**Fact.** The release contains eight root models and six imported metaschemas.
`assessment-results` requires `uuid`, `metadata`, `import-ap`, and at least one
`result`. Each result requires `uuid`, `title`, `description`, `start`, and
`reviewed-controls`.

**Fact.** `import-ap/@href` may be an absolute URI, relative reference, or bare
fragment resolving to a back-matter resource. Assessment Results therefore
does not need a separately transported Assessment Plan file, but the governing
plan reference and its semantics remain mandatory. The Assessment Plan in turn
imports a System Security Plan.

**Fact.** NIST lists assessors and continuous-assessment tools as Assessment
Results authors. A tool may author a document when its host supplies the
assessment context. The format does not grant a generic library enough context
to invent that plan, system, scope, or authority.

**Fact.** Observations, risks, and findings are separate collections. An
observation records what was observed and its evidence. A finding is an
assessor conclusion and may target a control statement or objective.
`finding/target/status/state` is the closed binary `satisfied` or
`not-satisfied`. Optional `implementation-status` can qualify degree of
implementation; namespace-qualified `prop` values are the sanctioned extension
mechanism for other machine-readable data.

**Fact.** `observation/relevant-evidence/description` is a human-readable
description of evidence. It is not a status or claim-strength field. Arbitrary
data belongs in a `prop` or `link`, not in `description` or `remarks`.

**Fact.** The core model has no document-signature field. Relevant evidence may
reference a back-matter resource. An external `rlink` requires `href` and may
carry hashes such as SHA-256, binding bytes at a reference for verification and
change detection. That hash does not authenticate an assessor, origin actor,
or issuance time. Inline `base64` content has no sibling hash field.

**Inference.** An OSCAL document can preserve a digest reference to SigilGuard
evidence, but it cannot make the projection cryptographically equivalent to
that evidence. Consumers must be told which artifact is authoritative and
which properties were not projected.

### Assessment Authority And Control Semantics

R.06 grades SigilGuard's own defenses with terms including `mitigates`,
`detects`, compound and partial variants, and `out-of-scope`. These are static
threat-model claims about this library. They are not runtime fields and are not
assessment conclusions about a particular deployed system.

The current runtime evidence does not identify a governing Assessment Plan,
System Security Plan, control objective, assessment population, sampling rule,
procedure, or assessor policy. A boundary verdict such as `block` proves what
SigilGuard decided for that boundary input. It does not prove that a system
control is satisfied.

**Inference.** Automatically translating R.06 labels or boundary verdicts into
OSCAL findings would overclaim both scope and authority.

**Recommendation.** The adapter may produce observations only after the host
provides a non-fragment Assessment Plan locator, exact reviewed-control set,
collection window, stable document identity, evidence location and digest, and
each observation-to-control association. Although OSCAL permits a bare fragment
when a plan is embedded in back matter, this adapter does not embed an
Assessment Plan and therefore cannot safely emit such a reference. Findings,
risks, assessment attestations, and binary conclusions remain
host/assessor-owned and outside the adapter.

### SigilGuard's Authoritative Evidence Boundary

The audit export is a canonical map containing a checkpoint and optional
anchor/proof material; it does not contain raw audit events. Its digest covers
the finalized export map. Verifying it against the chain requires the raw
events, and authenticating signatures or anchors requires host trust material
and verification options.

The optional checkpoint Statement in an export is compared with the checkpoint
digest by `Audit.Export.verify/3`; that comparison does not itself authenticate
the Statement envelope. A caller must apply the appropriate checkpoint,
witness, anchor, and chain verification policy before treating the package as
trusted.

**Recommendation.** `SP.17` defines the authoritative reference as the exact
bytes returned by `Audit.Export.canonical_bytes/1` plus their externally pinned
SHA-256 digest. Projection requires that expected digest and rejects a
mismatch. The host must publish those canonical bytes without JSON
reformatting; otherwise an OSCAL consumer hashing the `rlink` resource would
observe a different digest. The adapter does not claim that it performed the
host's complete trust-policy verification.

The projection MUST be a separate artifact. Embedding it in the export would
either change the compatibility bytes or create a circular digest when the
projection references that export.

### Detached Signing Prior Art

OSCAL issues requesting JWS and XMLDSig were closed `not_planned` in 2023. The
maintainers recommended external envelope solutions to avoid format-conversion
problems, but did not publish an OSCAL signing profile.

Compliance Trestle demonstrates a detached DSSE construction: an OSCAL JSON
document is canonicalized, hashed, placed in an in-toto Statement subject, and
described by an integrity-metadata predicate. Its OSCAL signing predicate
records canonicalization, digest source, and tool information; it does not add
a control conclusion or a signing-time field. Its package predicate is a
separate multi-document construction. Evidentia independently uses a subject
digest and can register related material through Sigstore/Rekor.

The in-toto predicate registry has no published compliance-assessment
predicate. The proposed OpenSSF Baseline predicate remains open and unmerged as
of the review date.

**Inference.** Detached signing is established prior art, but neither it nor a
novel predicate solves assessment authority. A claim-carrying SigilGuard
predicate would also require a new media-type, subject, and trust-profile
contract because the current envelope and Statement builders are deliberately
closed.

**Recommendation.** `SP.17` does not define a new signed Statement. If signed
OSCAL interoperability is later required, it needs separate research and a
versioned profile compatible with the chosen external construction.

### SCITT And Transparency

**Fact.** RFC 9943 and RFC 9942 are Standards Track. A receipt can be verified
offline from material already in hand. Registration requires a transparency
service, while non-equivocation detection requires auditors or relying parties
to compare service views. Revocation is outside the architecture's scope.

**Fact.** RFC 9162 is Experimental. Its inclusion proof establishes membership
under a named root, and its consistency proof establishes append-only growth
between named roots. Neither independently proves that a root is the unique
view shown to all clients; RFC 9162 does not specify gossip.

**Inference.** Local checkpoint and witness verification supplies useful
offline integrity and corroboration, but not every transparency-service
property. D4's no-network-core decision remains valid; its "equivalent
properties offline" rationale is too broad and must be corrected.

## Comparative Analysis

| Criterion | Inferred OSCAL findings | Host-context observation projection | SCITT registration |
|-----------|-------------------------|-------------------------------------|--------------------|
| Security | Overclaims assessment authority | Preserves authority boundary | Adds service trust and operations |
| Compatibility | Native format, false semantics | Native format, explicit loss markers | Not directly consumed as Assessment Results |
| Operational fit | Missing plan/system context | Pure, offline adapter | Registration is networked |
| Existing contracts | Tempts export/Statement changes | Leaves export and statements unchanged | Requires a post-GA adapter |
| Effort | Moderate and unsafe | Moderate; strict context and schema tests | High |
| Decision | rejected | adopted | deferred under D4 |

## Recommendation

**Decision: adopted.** Implement a pure `SigilGuard.Assessment.OSCAL.project/2`
adapter governed by `SP.17` with these binding constraints:

1. The first input is a finalized `SigilGuard.Audit.Export` map. The second is
   a closed, host-supplied assessment context.
2. The context includes a pinned expected export digest. Projection fails when
   the computed digest differs.
3. The output is OSCAL Assessment Results v1.2.3 with exact reviewed controls,
   one or more host-authorized observations, and a back-matter `rlink` carrying
   the SHA-256 digest of the canonical export bytes. Plan and evidence inputs
   must locate distinct resources; fragment/query-only references are rejected.
4. SigilGuard-specific values use the namespace
   `https://sigilguard.dev/ns/oscal`. Loss markers are machine-readable props;
   evidence descriptions remain descriptions.
5. The adapter emits no findings, risks, assessment attestations, or control
   satisfaction states. It never derives claims from R.06 labels or event
   verdicts.
6. Child UUIDs are deterministic UUIDv5 values derived from the host's stable
   Assessment Results UUID and the evidence/context content. The adapter reads
   no clock, process state, application environment, or network.
7. Existing `Audit.Export`, `Attestation.Statement`, `Attestation.Envelope`,
   and `TrustProfile` bytes and registries remain unchanged.

## Impact On SigilGuard

- **Modules affected:** create `SigilGuard.Assessment.OSCAL`; add it to ExDoc.
  `SigilGuard.Audit.Export` is consumed but unchanged.
- **Specs to create/update:** create `SP.17`; add its matching task; link it
  from the research and spec indexes. Correct D4's rationale without changing
  its no-network-core decision. D7 remains unchanged.
- **Migration needed:** none. The API and artifact are additive and optional.
- **Breaking changes:** none.

## Sources

- [OSCAL v1.2.3 metaschema sources](https://github.com/usnistgov/OSCAL/tree/v1.2.3/src/metaschema)
- [OSCAL Assessment Results model](https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-results/)
- [OSCAL issue 245: JWS support](https://github.com/usnistgov/OSCAL/issues/245)
- [OSCAL issue 345: XMLDSig support](https://github.com/usnistgov/OSCAL/issues/345)
- [OSCAL issue 841: flexible finding status](https://github.com/usnistgov/OSCAL/issues/841)
- [RFC 9943: SCITT Architecture](https://www.rfc-editor.org/rfc/rfc9943.html)
- [RFC 9942: COSE Receipts](https://www.rfc-editor.org/rfc/rfc9942.html)
- [RFC 9162: Certificate Transparency Version 2.0](https://www.rfc-editor.org/rfc/rfc9162.html)
- [Compliance Trestle OSCAL signing predicate](https://oscal-compass.dev/compliance-trestle/latest/predicates/oscal-signing/v1/)
- [Compliance Trestle OSCAL package predicate](https://oscal-compass.dev/compliance-trestle/latest/predicates/oscal-package/v1/)
- [Evidentia source](https://github.com/polycentric-labs/evidentia)
- [in-toto predicate specifications](https://github.com/in-toto/attestation/tree/main/spec/predicates)
- [in-toto Reference predicate](https://github.com/in-toto/attestation/blob/main/spec/predicates/reference.md)
- [OpenSSF Baseline predicate proposal](https://github.com/in-toto/attestation/pull/502)
