# Migrating To SigilGuard 3.0

## MCP JSON-RPC Rejection Codes

SigilGuard 3.0 moves MCP gateway rejection codes from the v0.2 `-32001..-32003`
range to the dedicated `-32050..-32056` range:

| v0.2 code | v3 code | Status |
|-----------|---------|--------|
| `-32001` | `-32050` | `blocked` |
| `-32002` | `-32051` | `confirmation_required` |
| `-32003` | `-32052` | `quarantined` |
| n/a | `-32053` | `manifest_drift` |
| n/a | `-32054` | `unknown_manifest` |
| n/a | `-32055` | `invalid_attestation` |
| n/a | `-32056` | `sandbox_required` |

Clients should key retry, approval, quarantine, manifest refresh, attestation,
and sandbox handling off `error.data.status` rather than the older three-code
bucket.

## Decision Struct And The Unified Verdict (SP.07)

The runtime gate now evaluates through `SigilGuard.BoundaryPolicy` (SP.04) and
`%SigilGuard.Decision{}` carries the unified verdict enum on `:action`:

- **`:action` is the unified verdict** `:allow | :redact | :confirm | :quarantine
  | :block`. A confirming decision's `:action` is `:confirm`; the executable
  action to run after confirmation moves to the new `:effect` field
  (`:allow | :redact | :quarantine | nil`). Code that read `decision.action` to
  decide what to execute after a confirmation must read `decision.effect`. In
  particular, a `tool_result` prompt-injection decision that used to report
  `action: :quarantine` now reports `action: :confirm, effect: :quarantine`.
- **`:verdict` (v2 dual vocabulary)** — `:allowed | :blocked | {:confirm, reason}`
  — is still populated for compatibility and is removed in the M6 wave.
- **New fields**: `matched_rules` (`[%{rule_id, explanation}]`), `evidence_refs`,
  `effect`, and the boundary labels `source`, `sink`, `trust_zone`, `actor`,
  `resource`. The `:require_approval` repo action is closed to `:confirm`.
- **Facades unchanged (D17)**: `SigilGuard.scan/1`, `scan_and_redact/1`, and
  `policy_verdict/3` return shapes are byte-identical; hit maps gained additive
  optional keys only.
- **Sandbox matrix** applies in the gate only when a call declares a `tool` or
  `sandbox` (opt-in by presence); it does not auto-quarantine tool calls that
  declare neither.
- The confirmation token's informational `"action"` claim now records the
  unified action (`"confirm"` for confirming decisions); the token's
  cryptographic binding is unchanged.
