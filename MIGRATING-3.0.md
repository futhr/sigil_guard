# Migrating To SigilGuard 3.0

## Dependency Update

Update the package requirement when you are ready to adopt the v3 breaking
surface:

```elixir
# v2
{:sigil_guard, "~> 0.2"}

# v3
{:sigil_guard, "~> 3.0"}
```

Release candidates require an exact pin such as `"3.0.0-rc.1"`; `~> 3.0` does
not match prerelease versions.

## Migration Checklist

- Rename policy files to the SIGILGUARD filename family.
- Move MCP trust metadata from `_sigil` to `_agent_trust`.
- Move MCP confirmation metadata from `_sigil_confirmation` to
  `_agent_confirmation`.
- Replace the removed registry namespace with local or embedded
  `SigilGuard.TrustBundle` sources.
- Replace verdict envelopes with Agent Trust attestations.
- Replace profile compatibility calls with `SigilGuard.TrustProfile`.
- Remove deleted v2 configuration keys before booting v3.
- Update expected error atoms and boot-error handling.

## Policy Filenames

SigilGuard 3.0 renames repo policy files from the old SIGIL filename family
to the SIGILGUARD filename family. Legacy filenames fail closed with
`{:error, {:legacy_policy_filename, found, use}}` and are never parsed as
fallbacks.

| V2 Filename | V3 Filename |
|-------------|-------------|
| `SIGIL_POLICY` | `SIGILGUARD_POLICY` |
| `.sigil-policy` | `.sigilguard-policy` |
| `.sigil/policy` | `.sigilguard/policy` |
| `.github/sigil-policy` | `.github/sigilguard-policy` |

## MCP Trust Metadata

Use `_agent_trust` instead of `_sigil` for Agent Trust attestations attached to
MCP payloads. Literal before/after payload examples are filled in by M6.14.

## MCP Confirmation Metadata

Use `_agent_confirmation` instead of `_sigil_confirmation` for confirmation
metadata. Literal payload examples and the `:confirmation_token` option path are
filled in by M6.15.

## Registry To Trust Bundles

The `SigilGuard.Registry` namespace is removed. Migrate to verified trust bundle
sources loaded by `SigilGuard.TrustBundle`.

### Fetch Bundle

`SigilGuard.Registry.fetch_bundle/1` maps to `SigilGuard.TrustBundle.load/1`.
Source-construction examples for `{:file, path}`, `{:priv, app, path}`, and
`{:binary, bytes}` are filled in by M6.16.

### Resolve DID And Key

`SigilGuard.Registry.resolve_did/2` moves to host authentication or verified
bundle issuer lookup. `SigilGuard.Registry.resolve_key/2` moves to verified
bundle root/delegation lookup. Exact examples are filled in by M6.17.

### Fetch Policies

`SigilGuard.Registry.fetch_policies/1` maps to the verified trust bundle
`policies` section.

### Bundle Signing And Cache

`SigilGuard.Registry.Bundle.sign/2` maps to trust-bundle provenance signing.
`SigilGuard.Registry.Cache` maps to `SigilGuard.TrustBundle.Cache`.

## Envelope To Attestation

`SigilGuard.Envelope` is removed. Use `SigilGuard.Attestation` and Agent Trust
DSSE envelopes. The SP.01 field mapping table and known consumer call-site
replacement snippets are filled in by M6.18.

## Profile To TrustProfile

`SigilGuard.Profile` is removed. Use `SigilGuard.TrustProfile` for the v3 Agent
Trust profile. Function-level mapping and profile-id constant guidance are
filled in by M6.19.

## Configuration Keys

Remove deleted v2 keys before booting v3. Removed keys fail closed with
`SigilGuard.ConfigError` naming `MIGRATING-3.0.md`; the complete per-key table is
filled in by M6.20.

## Error Changes

Some v2 error atoms were reconciled for v3 trust-bundle and configuration
contracts. The old-to-new atom table and new boot-error behavior are filled in
by M6.21.

## Version Pinning

`~> 0.2` users do not auto-upgrade to v3. Release-candidate and final-release
pinning guidance is expanded by M6.22.

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
