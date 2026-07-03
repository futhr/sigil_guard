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
