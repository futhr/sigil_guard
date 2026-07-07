---
sigil_guard:
  id: "R.02"
  topic: "Attestation Envelope And Canonical Encoding"
  category: research
  status: complete
  created: "2026-07-02"
  updated: "2026-07-02"
  decision: adopted
  tags:
    [
      "attestation",
      "dsse",
      "jcs",
      "canonical-encoding",
      "in-toto",
      "trust-bundles",
      "audit"
    ]
---

# R.02 - Attestation Envelope And Canonical Encoding

## Executive Summary

SigilGuard v3 signs every external artifact — runtime attestations, trust
bundles, audit checkpoints, and audit export packages — as a **DSSE envelope
wrapping a JCS-canonical (RFC 8785) JSON payload shaped as an in-toto-style
Statement**. DSSE's Pre-Authentication Encoding signs opaque bytes, which
removes JSON canonicalization from the signature trust path entirely. The
DSSE multi-signature array provides witness cosigning and m-of-n thresholds
without any custom envelope design. The in-toto Statement shape (subject
digests plus a `predicateType` URI) gives free interoperability with cosign,
Rekor, and GUAC tooling. JCS keeps the payload human-readable and
byte-deterministic for digests and golden vectors.

**Decision: adopted.** This note records decision D1 and closes R.01's first
deferred item, the open canonicalization questions carried into SP.01, and
the task-list open decision "plain JCS JSON vs DSSE-style envelope".

## Research Question

Which external encoding must SigilGuard v3 use for the signed bytes of all
Agent Trust Profile artifacts, given the following constraints?

1. **Offline.** Signing and verification run with no network access. Trust
   material is local (R.01, SP.02). Nothing in the encoding may assume a
   resolver, registry, or online timestamp authority.
2. **Dependency-light.** The v3 core runtime dependency set is telemetry
   only (D9). The encoding must be implementable with OTP `:crypto`, the
   built-in `JSON` module (Elixir >= 1.18), and hand-rolled pure Elixir.
3. **Lesser-model-implementable.** Every byte of the signed representation
   must be specified exactly — preimage formula, field names, base64
   alphabet, key ordering, number formatting — so an implementer needs zero
   judgment calls.
4. **Single verification code path.** Attestations, trust bundles,
   checkpoints, and exports must verify through one shared envelope
   verifier, not four artifact-specific signature schemes.
5. **Multi-signature capable.** Bundle role thresholds (D3) and audit
   checkpoint witness cosigning (D10) require multiple independent
   signatures over the same bytes.
6. **Ecosystem-legible.** External verifiers and supply-chain tooling
   should be able to consume SigilGuard artifacts without SigilGuard code.

## Methodology

Primary specifications reviewed:

- DSSE protocol specification v1.0 (secure-systems-lab), including the PAE
  definition, envelope JSON shape, and multi-signature semantics.
- RFC 8785 JSON Canonicalization Scheme, including its number-serialization
  rules, property-sorting rules, and appendix test material, plus RFC 7493
  (I-JSON) for the interoperable integer range.
- in-toto Attestation Framework v1: Statement layer, subject digest sets,
  and predicate registration conventions.
- Sigstore bundle format documentation (DSSE envelopes as bundle content)
  and SLSA v1 build provenance (a deployed in-toto predicate).
- COSE (RFC 9052) with CBOR (RFC 8949) and the CBOR Common Deterministic
  Encoding draft, as the binary alternative.

Findings were cross-checked against the existing SigilGuard codebase
(envelope canonical bytes, Ed25519 checkpoint signing, HMAC audit chain) and
against decisions D3 (bundle role thresholds) and D10 (witness cosigning),
which impose the multi-signature requirement. Where sources conflicted, the
analysis favored designs in which signature validity never depends on
canonicalization correctness, because canonicalization bugs are the
historical failure mode of signed JSON.

## Context

R.01 adopted typed attestations over canonical digests but deferred the
external encoding: "pure canonical JSON, JCS, DSSE, COSE, or a dual
internal/external representation". SP.01's Canonicalization Decision section
picked RFC 8785 for external bytes but left the envelope question open. The
task list carries the same item as an open decision. Every v3 spec that
defines a signed artifact — SP.01 (attestations), SP.02 (trust bundles),
SP.05 (checkpoints, exports, witnessing), SP.13 (agent cards and
agent-to-agent statements) — is blocked on this choice, because canonical
examples and golden vectors cannot be written until the outer bytes are
fixed. This note closes the decision so those specs can copy exact
constants from one place.

## Findings

### DSSE Envelope Mechanics

DSSE (Dead Simple Signing Envelope) separates "what is signed" from "how it
is transported". The envelope is ordinary JSON with three fields:

| Field | Type | Content |
|-------|------|---------|
| `payload` | string | base64url of the serialized statement bytes. |
| `payloadType` | string | Media type of the payload; part of the preimage. |
| `signatures` | list | One or more `{keyid, sig}` maps. |

The signature is never computed over the payload directly and never over
the envelope JSON. It is computed over the Pre-Authentication Encoding:

```
PAE(type, body) = "DSSEv1" SP len(type) SP type SP len(body) SP body
```

where `SP` is a single space (0x20) and `len(...)` is the ASCII decimal
byte count of the following field. For SigilGuard's payload type (31 bytes)
and an illustrative 7-byte body `{"x":1}`:

```
DSSEv1 31 application/vnd.sigilguard+json 7 {"x":1}
```

Three properties follow from PAE and drive the adoption decision:

1. **Canonicalization is out of the trust path.** The verifier base64url-
   decodes `payload`, builds PAE from the received bytes, and verifies the
   signature over those exact bytes. It MUST NOT re-serialize or
   re-canonicalize the payload before signature verification. A signer and
   verifier can therefore disagree about JSON serialization details without
   any security consequence; the signed object is an opaque byte string.
2. **The encoding is injective.** The length prefixes make it impossible
   for two distinct `(type, body)` pairs to produce the same PAE bytes, so
   boundary-shifting and type-confusion attacks on the preimage are
   structurally excluded. Binding `payloadType` inside the preimage means a
   signature over a SigilGuard statement can never be replayed as a
   signature over some other JSON format.
3. **Envelope serialization is free.** Because the signature covers PAE
   bytes rather than envelope JSON, the envelope itself may be
   pretty-printed, re-ordered, or re-serialized in transit without breaking
   verification. Only the decoded payload bytes matter.

The `signatures` array carries independent signatures over the same PAE
bytes. This provides, with zero custom design: witness cosigning (a witness
appends its `{keyid, sig}` entry without touching the payload or existing
signatures) and m-of-n threshold verification (the verifier counts valid
signatures from distinct authorized key ids against a role threshold, per
D3/R.03). `keyid` is an unauthenticated hint. Verifiers MUST resolve keys
through the trust bundle and MUST NOT treat `keyid` alone as authorization.
Envelopes containing duplicate `keyid` values in `signatures` MUST be
rejected. Implementation effort is small: roughly 300 lines of pure Elixir
for envelope encode/decode, PAE, and multi-signature verification.

### in-toto Statement Model

The payload inside the envelope is an in-toto-style Statement:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "tool_request",
      "digest": {
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }
    }
  ],
  "predicateType": "https://sigilguard.dev/attestation/tool_request/v1",
  "predicate": {
    "profile": "sigil_guard_agent_trust/v1"
  }
}
```

(The digest above is illustrative — SHA-256 of empty input. SP.01 defines
the real per-type digest field lists and golden vectors; predicates carry
the SP.01 attestation fields.)

The Statement layer contributes two things the raw payload would lack:

- **Subject digests.** `subject` binds the statement to the exact artifact
  bytes it describes, as `{name, digest: {sha256}}` entries. For SigilGuard
  this carries the action/payload/context/manifest digests that make
  attestations replay- and tamper-evident.
- **Typed dispatch.** `predicateType` is a URI that names the predicate
  schema. Verifiers dispatch on it with a closed map; unknown values MUST
  fail with `:unknown_statement_type` (SP.01 error taxonomy) rather than
  being interpreted loosely.

SigilGuard registers one predicate type per statement type (D7's eight
types) plus one for trust-bundle state:

| Statement type | `predicateType` URI |
|----------------|---------------------|
| `tool_request` | `https://sigilguard.dev/attestation/tool_request/v1` |
| `tool_result` | `https://sigilguard.dev/attestation/tool_result/v1` |
| `model_ingress` | `https://sigilguard.dev/attestation/model_ingress/v1` |
| `model_egress` | `https://sigilguard.dev/attestation/model_egress/v1` |
| `repo_change` | `https://sigilguard.dev/attestation/repo_change/v1` |
| `release` | `https://sigilguard.dev/attestation/release/v1` |
| `agent_request` | `https://sigilguard.dev/attestation/agent_request/v1` |
| `agent_response` | `https://sigilguard.dev/attestation/agent_response/v1` |
| trust-bundle state | `https://sigilguard.dev/trust-bundle-state/v1` |

Predicates embed the profile id `sigil_guard_agent_trust/v1` (SP.01), so an
artifact is self-describing at three levels: envelope (`payloadType`),
statement (`_type`, `predicateType`), and profile (`predicate.profile`).

The interoperability payoff is concrete. DSSE-wrapped in-toto Statements
are the native artifact format of the modern supply-chain stack: SLSA
provenance is an in-toto predicate, Sigstore bundles carry DSSE envelopes,
cosign signs and verifies them, Rekor logs them, and GUAC ingests them.
A SigilGuard release or trust-bundle attestation is therefore consumable by
existing tooling with no SigilGuard code, and future transparency-log
anchoring (R.04) needs no re-encoding. Statement building and validation is
roughly 400 lines of pure Elixir.

### JCS Payload Role

DSSE makes canonicalization unnecessary for signature verification, but
SigilGuard still canonicalizes the payload at emission time with RFC 8785
(JCS), for three reasons:

1. **Deterministic digests.** Subject digests, action/payload/context/
   manifest digests, bundle digests, and audit event hashes are computed
   over JCS bytes. Two independent implementations hashing the same logical
   object MUST produce the same digest.
2. **Golden vectors.** A fixed input (seeded key, fixed timestamp, fixed
   nonce) MUST produce byte-identical payloads, PAE bytes, and signatures
   across implementations and releases. That is only possible if emission
   is canonical.
3. **Human readability.** The payload stays plain JSON: one base64url
   decode away from inspectable, diffable text. Auditors and incident
   responders read evidence without binary tooling.

The division of labor is strict: JCS provides determinism at emission;
DSSE provides integrity at verification. Signature validity never depends
on JCS correctness, so a canonicalization bug can break vector stability
but can never make a forged artifact verify. RFC 8785 is an Independent
Submission stream RFC, frozen since 2020 and not an IETF-consensus
standard; that status is acceptable for an emission-side determinism rule
and is precisely why it is not trusted as the signature boundary — the
DSSE outer layer carries that responsibility.

### JCS Implementation Pitfalls

This subsection is normative for the `SigilGuard.Canonical.JCS`
implementer. RFC 8785 is short but its edge cases are exactly where
independent implementations diverge.

- **Integer range.** Integers outside ±2^53 MUST be carried as JSON
  strings in SigilGuard payloads. JCS serializes numbers as IEEE 754
  doubles; the interoperable integer range per I-JSON (RFC 7493) is
  [-(2^53 - 1), 2^53 - 1]. Values outside it silently lose precision.
  The encoder MUST return `{:error, :unsupported_number_range}` for
  integers outside that range instead of emitting a lossy double. Schema
  fields that can grow (sequence numbers, sizes, counters) MUST be defined
  as strings in SP.01/SP.02 if they can ever exceed the range.
- **Property sorting is by UTF-16 code units.** Keys sort by comparing
  their UTF-16 code-unit sequences, not Unicode code points and not UTF-8
  bytes. The three orders diverge for supplementary-plane characters.
  Concrete example: the key `"😀"` (U+1F600, UTF-16 surrogate pair
  `0xD83D 0xDE00`, UTF-8 `F0 9F 98 80`) and the key `"ﬀ"` (U+FB00, UTF-16
  `0xFB00`, UTF-8 `EF AC 80`). JCS compares first code units
  `0xD83D < 0xFB00`, so `"😀"` sorts before `"ﬀ"`. Code-point order and
  UTF-8 byte order both put `"ﬀ"` first — so a naive
  `Enum.sort/1` over Elixir's UTF-8 binaries produces wrong bytes. The
  encoder MUST sort by UTF-16 code units; converting each key with
  `:unicode.characters_to_binary(key, :utf8, {:utf16, :big})` and
  comparing the resulting binaries byte-wise is a correct implementation.
- **No Unicode normalization.** JCS applies no NFC/NFD normalization. The
  key `"é"` as U+00E9 and the key `"é"` as U+0065 U+0301 are distinct
  properties and may legally coexist in one object. The encoder MUST NOT
  normalize keys or string values; it MUST preserve the code points it was
  given.
- **ECMAScript number serialization.** Numbers serialize exactly per
  ECMA-262 `Number::toString` (the `JSON.stringify` rules): shortest
  round-trip form, `1.0` emits `1`, `-0` emits `0`, exponent form uses
  `e+`/`e-` starting at 10^21 (`1e+21`). Erlang/OTP's
  `:erlang.float_to_binary(f, [:short])` provides shortest round-trip
  digits (OTP >= 24) but formats integral floats and exponents differently
  (`1.0`, `1.0e21`), so the encoder MUST post-process into the ECMAScript
  surface form.
- **Non-finite numbers are errors.** `NaN` and `Infinity` have no JSON
  representation. The encoder MUST reject them with an error tuple (atom
  defined in the SP.01 shared taxonomy); it MUST NOT emit `null` or a
  string in their place.
- **String escaping is minimal.** Per RFC 8785, strings escape only `\"`,
  `\\`, the control shorthands (`\b`, `\t`, `\n`, `\f`, `\r`), and
  remaining control characters below U+0020 as lowercase `\uXXXX`. All
  other characters, including non-ASCII, are emitted literally as UTF-8.
- **Decode-side strictness.** Parsing uses the built-in `JSON` module;
  JCS constrains emission only. Decoders MUST reject duplicate object keys
  and malformed UTF-8 (including lone surrogates) rather than last-wins
  merging, per I-JSON.

A hand-rolled encoder meeting these rules is approximately 200 lines of
Elixir; the difficulty is concentrated in number formatting and key
sorting, not volume. The implementation MUST ship with an adversarial test
corpus including: the RFC 8785 appendix vectors (property-sorting sample
and number-serialization samples), surrogate-pair keys as above, NFC/NFD
twin keys, integers at and beyond the ±(2^53 - 1) boundary, `-0`, the
10^21 exponent boundary, deeply nested structures, duplicate-key rejection,
and lone-surrogate rejection. Property-based tests MUST assert
encode-decode-encode stability.

### Profile Constants (Normative)

Other documents copy these exact strings; they are defined here once.

- `payloadType`: `application/vnd.sigilguard+json`
- PAE preimage: `"DSSEv1" SP len(type) SP type SP len(body) SP body`,
  where lengths are ASCII decimal byte counts and `SP` = 0x20.
- DSSE envelope fields: `payload` (base64url of statement bytes),
  `payloadType`, `signatures: [{keyid, sig}]`.
- Statement: `_type: "https://in-toto.io/Statement/v1"`,
  `subject: [{name, digest: {sha256}}]`, `predicateType`, `predicate`.
- `predicateType` URIs: `https://sigilguard.dev/attestation/<statement-type>/v1`
  for the eight statement types (`tool_request`, `tool_result`,
  `model_ingress`, `model_egress`, `repo_change`, `release`,
  `agent_request`, `agent_response`), plus
  `https://sigilguard.dev/trust-bundle-state/v1` for bundle state.
- Profile id: `sigil_guard_agent_trust/v1`.
- Signatures: Ed25519 via OTP `:crypto`; `payload` and `sig` are base64url
  without padding. The DSSE specification tolerates both base64 alphabets
  on parse; SigilGuard emission MUST use base64url without padding.

## Comparative Analysis

| Criterion | JCS-only + embedded signature | DSSE + JCS payload (adopted) | COSE/CBOR |
|-----------|-------------------------------|------------------------------|-----------|
| Canonicalization attack surface | High: verifier re-canonicalizes before verify; every JCS divergence is a forgery or DoS vector | None: signature covers opaque PAE bytes; JCS is emission-only | Low for signing, but digest interop needs deterministic CBOR |
| Multi-signature support | None; requires inventing a custom envelope | Native `signatures` array; witnesses and m-of-n free | `COSE_Sign` supports multiple signers |
| Human readability | Full | Payload readable after one base64url decode | Binary; requires CBOR tooling |
| Ecosystem interop | None for this niche | cosign, Rekor, GUAC, in-toto, SLSA, Sigstore bundles | SCITT/IoT ecosystems; weak in agent/supply-chain tooling |
| Pure-Elixir effort | ~200 LOC, plus a custom signature scheme to design | ~900 LOC total (JCS ~200, DSSE ~300, Statement ~400) | CBOR codec + deterministic profile + COSE structures, well beyond 1k LOC plus draft tracking |
| Offline capability | Full | Full | Full |

**Why JCS-only is rejected.** Signing canonicalized JSON directly means the
verifier MUST re-canonicalize received JSON before checking the signature,
which re-opens the canonicalization attack surface this design exists to
close: any divergence between two JCS implementations (number formatting,
key sorting, normalization handling) becomes a verification bypass or a
signed-bytes mismatch. It also provides no signature envelope, so witness
cosigning and m-of-n thresholds (D3, D10) would require a bespoke
multi-signature container — reinventing DSSE badly. Embedding the signature
inside the signed object additionally forces a strip-then-canonicalize
step, a second source of divergence.

**Why COSE/CBOR is rejected.** COSE signs opaque bytes through
`Sig_structure` and is cryptographically sound, but it is binary: evidence
stops being human-readable, and every consumer needs CBOR tooling. Its
ecosystem gravity is SCITT and IoT, not the supply-chain and agent tooling
SigilGuard artifacts should interoperate with — cosign, Rekor, GUAC, and
SLSA all speak DSSE + in-toto. Deterministic CBOR for digest computation
adds its own canonicalization problem: RFC 8949 sketches core requirements,
but the interoperable profile (CBOR Common Deterministic Encoding) remains
an Internet-Draft. A pure-Elixir CBOR codec plus COSE structures is also
the largest implementation of the three options. COSE remains a possible
future SCITT adapter representation (D4) without changing the core format.

## Recommendation

**Decision:** adopted.

SigilGuard v3 adopts DSSE + JCS + in-toto-style Statement as the single
external encoding for all signed artifacts. Normative rules:

- Every externally signed artifact — runtime attestation, trust bundle,
  audit checkpoint, audit export — MUST be a DSSE envelope whose
  `payloadType` is exactly `application/vnd.sigilguard+json`.
- The payload MUST be a JCS-canonical (RFC 8785) Statement at emission,
  with `_type: "https://in-toto.io/Statement/v1"` and a registered
  SigilGuard `predicateType` URI.
- Signatures MUST be Ed25519 over the PAE bytes
  (`"DSSEv1" SP len(type) SP type SP len(body) SP body`), computed with
  OTP `:crypto`, encoded base64url without padding.
- Verifiers MUST verify signatures over the received payload bytes and
  MUST NOT re-canonicalize before signature verification. Digest
  recomputation of referenced artifacts uses JCS; signature checking never
  does.
- Verifiers MUST resolve `keyid` through the trust bundle, MUST reject
  duplicate key ids, and MUST enforce role thresholds where the bundle
  declares them.
- One verification code path MUST serve all four artifact classes; specs
  MUST NOT introduce artifact-specific signature schemes.

**Rationale:** the combination is the only option that removes
canonicalization from the trust path, provides multi-signature semantics
required by D3 and D10 without custom design, keeps evidence
human-readable, is proven at scale by Sigstore/in-toto/SLSA, and fits the
dependency budget (`:crypto` + built-in JSON + ~900 lines of hand-rolled
Elixir, fully offline).

**Closures.** This decision closes:

- R.01's first Deferred item ("whether the first external profile encoding
  should be pure canonical JSON, JCS, DSSE, COSE, or a dual
  internal/external representation") and R.01 Open Questions 1-2 (JCS-only
  vs internal-plus-export; DSSE now vs later — the answer is DSSE now, as
  the only representation).
- SP.01's open questions 1-2 left by its Canonicalization Decision section
  (external canonical bytes: JCS; public envelope: DSSE). SP.01 replaces
  that section with a normative "Attestation Envelope And Canonical
  Encoding" section copying the constants above.
- The task-list Open Decision "plain JCS JSON vs a DSSE-style envelope in
  v1.0".

## Impact On SigilGuard

- Modules affected: future `SigilGuard.Attestation` (DSSE sign/verify,
  `from_decision`), future `SigilGuard.Canonical.JCS` (hand-rolled encoder
  with the pitfalls corpus above), future `SigilGuard.TrustBundle` (bundle
  signing and threshold verification as DSSE payloads per D3),
  `SigilGuard.Audit` checkpoint signing and witness cosigning plus export
  packages (D10). `SigilGuard.Envelope` verdict signing is replaced, not
  extended.
- Specs to create/update: `SP.01` is the primary normative home (envelope
  field table, PAE formula, Statement shape, JCS pitfalls, golden
  vectors); `SP.02`, `SP.05`, and `SP.13` reference SP.01's encoding
  section instead of restating it.
- Migration needed: yes. Envelope verdict-signing maps to Attestation
  statements via the field mapping table in SP.01, documented 1:1 in
  `MIGRATING-1.0.md`; legacy envelope fixtures move to
  `test/fixtures/historical/`.
- Breaking changes: yes. v3 external signed bytes are not compatible with
  0.2.x envelope canonical bytes, and the public signing API changes.

## Sources

- [DSSE - Dead Simple Signing Envelope](https://github.com/secure-systems-lab/dsse)
- [DSSE Protocol Specification v1.0](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
- [RFC 8785 - JSON Canonicalization Scheme (Independent Submission, 2020)](https://www.rfc-editor.org/info/rfc8785)
- [RFC 7493 - The I-JSON Message Format](https://www.rfc-editor.org/info/rfc7493)
- [in-toto Attestation Framework](https://github.com/in-toto/attestation)
- [in-toto Statement v1 Specification](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
- [Sigstore Bundle Format](https://docs.sigstore.dev/about/bundle/)
- [SLSA Build Provenance](https://slsa.dev/spec/v1.2/build-provenance)
- [RFC 9052 - CBOR Object Signing and Encryption (COSE)](https://datatracker.ietf.org/doc/html/rfc9052)
- [RFC 8949 - Concise Binary Object Representation (CBOR)](https://datatracker.ietf.org/doc/html/rfc8949)
- [CBOR Common Deterministic Encoding (Internet-Draft)](https://datatracker.ietf.org/doc/draft-ietf-cbor-cde/)
- [ECMA-262 Number::toString](https://tc39.es/ecma262/#sec-numeric-types-number-tostring)
