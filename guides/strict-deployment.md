# Strict embedded deployment

Pin a host-approved genesis root before accepting replaceable bundle sources.
Embedding the first bundle in a release is the default trust bootstrap; it does
not authenticate arbitrary first-contact network input. Remote retrieval,
authentication, delivery timeouts and release provenance belong to the host.

Use `enforce_declared_threshold: true` when loading bundles. Rotation always
requires both declared root quorums. A rotated successor that introduces delegate
authority also needs the new root quorum to countersign its unchanged DSSE payload:
rotation v1 documents authenticate root keys, not the successor's delegates.
Keep the complete chain and persist host-approved rollback state across restarts.

Enable attestation replay consumption at execution boundaries. Confirmation
verification consumes by default; `consume: false` is inspection only. Replay
retention uses monotonic time and cannot be shortened below the complete accepted
UTC lifetime, including skew. Capacity exhaustion rejects new claims without
evicting live nonces. These stores are per node and per boot; distributed and
cross-boot replay protection require host coordination.

Resolve `SigilGuard.Runtime.scanner_options/2` at each boundary when using
`scanner_patterns: :bundle`, then pass those options to the gate or stream. An
expired or invalid configured bundle fails resolution. Bare scanner calls use
built-ins. Review custom regular expressions and apply host concurrency and
execution-time limits in addition to the library's input budgets.

The library defaults to 1 MiB of untrusted binary data, 100,000 term nodes and
64 container levels before normalization. Envelopes allow at most 64 signatures.
`SigilGuard.Scanner.scan/2` and the runtime gate accept `:max_input_bytes`,
`:max_input_nodes` and `:max_input_depth`; scanner budget errors raise
`ArgumentError`, while the gate returns a blocked decision. Trust diagnostics
retain the most recent 1,000 records. Rate and replay stores cap live identities
or claims at 100,000; the replay API can request a lower capacity explicitly.

Streaming retains incomplete built-in credential and instruction prefixes.
Custom expressions with unknown width, custom indicator sets and custom scanner
pipelines buffer until the end. `:max_stream_bytes` bounds pending bytes (1 MiB by
default); exhaustion, malformed UTF-8, block or confirmation stops further
emission. A finite `max_match_bytes` hint alone cannot prove an unbounded regex
safe. Hosts must not dispatch halted streams or treat partial output as a final
whole-message authorization.

Application maps containing null-valued fields cannot be signed under the v3
omission rule. Omit optional fields deliberately, or represent explicit clearing
as an application-defined operation/value. JSON null in arrays retains its
meaning. Fixed nullable MCP wrapper fields retain their profile semantics; this
exception does not apply to application arguments. Existing unambiguous v3
payload bytes, frozen vectors and confirmation preimages remain unchanged.

Require verified capability manifests for privileged tool execution. Tool names,
actor identity, resource URIs and digests are policy facts; a tool name by itself
is not verified side-effect evidence. Bind origin, sink, phase, trust zone and
sandbox facts from host-controlled context.

The MCP conformance suite tests a host transport adapter, not this transport-free
core. Run the [official suite](https://github.com/modelcontextprotocol/conformance)
against the actual host adapter in its release pipeline. SigilGuard's local
fixtures prove library contracts; they do not claim certification of a host or
full protection against prompt injection. The OWASP Agent Control Standard and
LLM Top 10 2026 provide control-mapping inputs; map verified library evidence and
host obligations separately as those documents evolve.
