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
MCP payloads. The metadata key may appear at the JSON-RPC payload root or inside
`params`; v3 strips `_agent_trust` from both locations before computing action
digests. V3 does not strip `_sigil`.

Before:

```json
{
  "jsonrpc": "2.0",
  "id": "call-1",
  "method": "tools/call",
  "params": {
    "name": "repo_file_write",
    "arguments": {
      "path": "docs/guide.md",
      "content": "updated"
    },
    "_sigil": {
      "identity": "spiffe://prod.example.org/agents/release-bot",
      "verdict": "allowed",
      "timestamp": "2026-07-02T12:00:00.000Z",
      "nonce": "000102030405060708090a0b0c0d0e0f",
      "signature": "legacy-base64url-signature"
    }
  }
}
```

After:

```json
{
  "jsonrpc": "2.0",
  "id": "call-1",
  "method": "tools/call",
  "params": {
    "name": "repo_file_write",
    "arguments": {
      "path": "docs/guide.md",
      "content": "updated"
    },
    "_agent_trust": {
      "payloadType": "application/vnd.sigilguard+json",
      "payload": "base64url-jcs-in-toto-statement",
      "signatures": [
        {
          "keyid": "sha256:65b60673d6ed884bf01c2c222d82ada0740f29ac3355d6a925c81f17f47a27b8",
          "sig": "base64url-dsse-signature"
        }
      ]
    }
  }
}
```

Mixed-traffic rollout: do not send both metadata keys to the same v3 endpoint.
Upgrade producers and consumers as a pair, or route v2 traffic to the old v2
deployment until both sides emit and verify `_agent_trust`. In v3, `_sigil` is
ordinary user content for digest purposes and can change the signed action
digest instead of being treated as transport metadata.

## MCP Confirmation Metadata

Use `_agent_confirmation` instead of `_sigil_confirmation` for confirmation
metadata. Like `_agent_trust`, v3 strips `_agent_confirmation` at the JSON-RPC
payload root and inside `params` before computing action digests.

Before:

```json
{
  "jsonrpc": "2.0",
  "id": "call-2",
  "method": "tools/call",
  "params": {
    "name": "send_webhook",
    "arguments": {
      "url": "https://hooks.example.invalid/deploy",
      "body": "deploy"
    },
    "_sigil_confirmation": "legacy-confirmation-token"
  }
}
```

After:

```json
{
  "jsonrpc": "2.0",
  "id": "call-2",
  "method": "tools/call",
  "params": {
    "name": "send_webhook",
    "arguments": {
      "url": "https://hooks.example.invalid/deploy",
      "body": "deploy"
    },
    "_agent_confirmation": "v3-confirmation-token"
  }
}
```

When the token is already held out-of-band, pass it through the existing
`:confirmation_token` option instead of embedding transport metadata:

```elixir
SigilGuard.MCP.Gateway.guard_confirmed_request(
  request,
  [trust_level: :medium],
  confirmation_token: token
)
```

The same option path applies to `guarded_confirmed_request/3`,
`guard_signed_confirmed_request/3`, `guarded_signed_confirmed_request/3`,
`guard_confirmed_result/3`, and `guarded_confirmed_result/3`.

## Registry To Trust Bundles

The `SigilGuard.Registry` namespace is removed. Migrate to verified trust bundle
sources loaded by `SigilGuard.TrustBundle`.

### Fetch Bundle

`SigilGuard.Registry.fetch_bundle/1` maps to `SigilGuard.TrustBundle.load/1`.

Before:

```elixir
{:ok, bundle} = SigilGuard.Registry.fetch_bundle("agent-policy")
```

After, for a bundle file managed by the host:

```elixir
source = {:file, "/etc/sigil_guard/trust_bundle.json"}
{:ok, bundle} = SigilGuard.TrustBundle.load(source)
```

After, for a bundle shipped in an OTP application's `priv/` directory:

```elixir
source = {:priv, :my_app, "sigil_guard/trust_bundle.json"}
{:ok, bundle} = SigilGuard.TrustBundle.load(source)
```

After, for bytes fetched by host-owned transport and accepted as the bundle
envelope JSON:

```elixir
source = {:binary, verified_bundle_json}
{:ok, bundle} = SigilGuard.TrustBundle.load(source)
```

`TrustBundle.load/1` verifies the DSSE envelope and bundle metadata before the
bundle enters the runtime. SigilGuard v3 does not fetch bundles from a registry;
if a host downloads bundle bytes, that transport, caching, authentication, and
retry policy live outside SigilGuard and feed only the `{:binary, bytes}` source.

### Resolve DID And Key

`SigilGuard.Registry.resolve_did/2` moves to host authentication or verified
bundle issuer lookup. `SigilGuard.Registry.resolve_key/2` moves to verified
bundle root/delegation lookup.

Before:

```elixir
{:ok, did_doc} = SigilGuard.Registry.resolve_did("did:web:agent.example", [])
{:ok, public_key} = SigilGuard.Registry.resolve_key("sha256:key-id", [])
```

After, for DID or actor identity flows, authenticate the principal in the host
and compare it with verified issuer policy from the bundle:

```elixir
{:ok, bundle} = SigilGuard.TrustBundle.load({:file, bundle_path})

allowed_issuers =
  bundle
  |> SigilGuard.TrustBundle.identity_issuers()
  |> MapSet.new()

if MapSet.member?(allowed_issuers, host_authenticated_actor_id) do
  {:ok, host_authenticated_actor_id}
else
  {:error, :unknown_issuer}
end
```

After, for key material used to verify attestations, resolve by `keyid` from the
verified bundle document and only accept keys authorized by the root or delegated
bundle roles:

```elixir
document = bundle.document
keys = Map.fetch!(document, "keys")
root_keyids = get_in(document, ["roles", "root", "keyids"]) || []

delegate_keyids =
  document
  |> get_in(["roles", "delegates"])
  |> List.wrap()
  |> Enum.flat_map(&Map.get(&1, "keyids", []))

authorized_keyids = MapSet.new(root_keyids ++ delegate_keyids)

trust_material =
  for {keyid, %{"public_key" => public_key}} <- keys,
      MapSet.member?(authorized_keyids, keyid),
      into: %{} do
    {keyid, public_key}
  end

SigilGuard.Attestation.verify(envelope, trust_material)
```

There is no DID resolver in v3 core. Network DID resolution, OAuth/resource
server identity, SPIFFE/SVID validation, and account-to-actor mapping remain
host-owned inputs to SigilGuard.

### Fetch Policies

`SigilGuard.Registry.fetch_policies/1` maps to the verified trust bundle
`policies` section.

### Bundle Signing And Cache

`SigilGuard.Registry.Bundle.sign/2` maps to trust-bundle provenance signing.
`SigilGuard.Registry.Cache` maps to `SigilGuard.TrustBundle.Cache`.

## Envelope To Attestation

`SigilGuard.Envelope` is removed. Use `SigilGuard.Attestation` and Agent Trust
DSSE envelopes.

The v2 verdict mapping is `:allowed -> "allow"`, `:blocked -> "block"`, and
`:scanned -> "allow"`; v2 `:scanned` was advisory, while v3 records scanner
evidence in `matched_rules`.

| V2 Envelope surface | V3 Attestation surface |
|---------------------|------------------------|
| `identity` | `predicate.actor.id` (issuer is the resolved signing key via `keyid`). |
| `verdict` (`allowed`/`blocked`/`scanned`) | `predicate.verdict` per the mapping above. |
| `timestamp` | `predicate.issued_at` (`expires_at` is new and required). |
| `nonce` (16-byte hex) | `predicate.nonce`, same format. |
| `signature` (single base64url string) | `signatures[0].sig` in the DSSE envelope, plus new `keyid`. |
| `reason` | `predicate.matched_rules[].explanation`. |
| Canonical bytes `{identity,nonce,timestamp,verdict}` | PAE over the base64url DSSE payload. |
| `profile:`/`wire_verdict_format:` options | Removed; one profile, one wire form. |
| `Envelope.sign(identity, verdict, opts)` | `Attestation.from_decision/3` + `Attestation.sign/3`. |
| `Envelope.verify(envelope, public_key_b64u, opts)` | `Attestation.verify(envelope, trust_material, opts)`. |
| `_sigil` | `_agent_trust` (`Attestation.attach/2`, `fetch/1`). |
| `_sigil_confirmation` | `_agent_confirmation` (`attach_confirmation/2`, `fetch_confirmation/1`). |
| Legacy envelope fixtures | Moved to `test/fixtures/historical/` (SP.06). |

### Signing A Tool Request

Before:

```elixir
{:ok, envelope} =
  SigilGuard.Envelope.sign("spiffe://prod.example.org/agents/release-bot", :allowed,
    reason: "repo write approved"
  )

request =
  update_in(request, ["params"], &Map.put(&1, "_sigil", envelope))
```

After:

```elixir
{:ok, statement} =
  SigilGuard.Attestation.from_decision(decision, context,
    payload: request,
    statement_type: :tool_request
  )

{:ok, envelope} =
  SigilGuard.Attestation.sign(statement, MyApp.AgentSigner,
    keyid: "sha256:65b60673d6ed884bf01c2c222d82ada0740f29ac3355d6a925c81f17f47a27b8"
  )

request = SigilGuard.Attestation.attach(request, envelope)
```

### Verifying An Attached Request

Before:

```elixir
with {:ok, envelope} <- Map.fetch(request["params"], "_sigil"),
     {:ok, claims} <- SigilGuard.Envelope.verify(envelope, public_key_b64u) do
  {:ok, claims}
end
```

After:

```elixir
trust_material = %{
  "sha256:65b60673d6ed884bf01c2c222d82ada0740f29ac3355d6a925c81f17f47a27b8" =>
    public_key_b64u
}

with {:ok, envelope} <- SigilGuard.Attestation.fetch(request),
     {:ok, statement} <-
       SigilGuard.Attestation.verify(envelope, trust_material,
         payload: request,
         context: context,
         consume: true
       ) do
  {:ok, statement}
end
```

The trust material can be a direct `%{keyid => public_key}` map or a map derived
from a verified trust bundle as shown in the registry lookup migration section.

## Profile To TrustProfile

`SigilGuard.Profile` is removed. Use `SigilGuard.TrustProfile` for the v3 Agent
Trust profile. V3 has one profile id and one wire form:
`sigil_guard_agent_trust/v1`.

| V2 Profile surface | V3 replacement |
|--------------------|----------------|
| `SigilGuard.Profile.profiles/0` | `SigilGuard.TrustProfile.statement_types/0` plus `predicate_type/1` for the closed statement registry. |
| `SigilGuard.Profile.normalize!/1` | Removed. Build or verify a v3 Statement and call `SigilGuard.TrustProfile.validate/1`; invalid profiles return typed errors instead of normalizing. |
| `SigilGuard.Profile.wire_verdict_format/1` | Removed. V3 uses one predicate verdict vocabulary in Agent Trust statements. |
| `SigilGuard.Profile.verdict_acceptance/1` | Removed. `SigilGuard.Attestation.verify/3` and `SigilGuard.TrustProfile.validate/1` enforce the v3 profile. |
| `SigilGuard.Profile.require_blocked_reason_on_verify?/1` | Removed. Blocking rationale lives in `predicate.matched_rules[].explanation`. |
| `SigilGuard.Profile.registry_identity_endpoints/1` | Removed. DID/network identity discovery is host-owned; verified bundle issuer policy is available through `SigilGuard.TrustBundle.identity_issuers/1`. |
| `:protocol_profile` config | Removed. Use `SigilGuard.TrustProfile.profile_id/0` when code needs the constant. |

Before:

```elixir
profile = SigilGuard.Profile.normalize!(:auto)
format = SigilGuard.Profile.wire_verdict_format(profile)
```

After:

```elixir
profile_id = SigilGuard.TrustProfile.profile_id()
statement_types = SigilGuard.TrustProfile.statement_types()
{:ok, predicate_type} = SigilGuard.TrustProfile.predicate_type(:tool_request)
```

For validation, do not normalize legacy profile names. Validate the produced or
received Agent Trust Statement:

```elixir
case SigilGuard.TrustProfile.validate(statement) do
  {:ok, statement} -> {:ok, statement}
  {:error, :unsupported_profile_version} -> {:error, :upgrade_required}
  {:error, reason} -> {:error, reason}
end
```

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
