# Release Verification and WORM Anchoring

This guide covers two host-owned operational surfaces: verifying a release's
SBOM and provenance, and implementing a write-once/read-many (WORM) or
append-only audit anchor store. SigilGuard ships the primitives; transport,
storage, and CI are owned by the host. The library performs no network calls
of its own in any decision path.

## Verifying a release SBOM

SigilGuard generates an SPDX 2.3 SBOM with the built-in Mix task. Generation
uses only the Mix project, `mix.lock`, and Jason — no network:

```bash
mix sigil_guard.sbom --output dist/sigil_guard.spdx.json
```

Verification has two levels. **Structural** verification checks the document
against the current project and lockfile:

```bash
mix sigil_guard.sbom --verify dist/sigil_guard.spdx.json
```

**Digest** verification additionally binds the file to the exact bytes attested
in the release provenance (the SLSA `attest-build-provenance` subject and the
`artifacts` list of the signed release statement). Compute the digest and pass it:

```bash
shasum -a 256 dist/sigil_guard.spdx.json
mix sigil_guard.sbom --verify dist/sigil_guard.spdx.json \
  --sha256 <expected-sha256-from-provenance>
```

If the SBOM on disk has drifted from the attested bytes, verification fails
fast with `:sbom_digest_mismatch` before any structural check runs. The digest
comparison is case-insensitive on the expected value.

Verify the build provenance itself with the GitHub CLI, gating publish on it:

```bash
gh attestation verify sigil_guard-1.0.0.tar --repo refpath/sigil_guard
```

### Consumer-side verification in CI

A downstream consumer gates its own build on the same evidence — provenance,
SBOM digest, and structure — before trusting the release:

```yaml
- name: Verify sigil_guard release
  env:
    GH_TOKEN: ${{ github.token }}
  run: |
    gh attestation verify sigil_guard-1.0.0.tar --repo refpath/sigil_guard
    gh attestation verify sigil_guard-1.0.0.spdx.json --repo refpath/sigil_guard
    mix sigil_guard.sbom \
      --verify sigil_guard-1.0.0.spdx.json \
      --sha256 "$(shasum -a 256 sigil_guard-1.0.0.spdx.json | cut -d' ' -f1)"
```

The tagged-release workflow produces these subjects with
`actions/attest-build-provenance`, signs the release statement
(`mix sigil_guard.release_statement`), and runs `gh attestation verify` itself
before `mix hex.publish`, so a failed verification blocks the publish.

## Implementing a WORM / append-only anchor store

Audit checkpoints and exports are the tamper-evidence layer; anchoring writes a
compact receipt to external storage so the chain tail cannot be silently
truncated. `SigilGuard.Audit.Anchor.Store.LocalFile` appends to a local file;
for durable WORM storage (object-lock buckets, transparency logs, WORM
appliances) a host provides an HTTP endpoint and reaches it through the
`SigilGuard.Audit.Anchor.Store.HTTP` adapter plus a `SigilGuard.HTTPClient`.

### The HTTP client seam

The anchor HTTP store performs no network itself — it routes every request
through a host-provided `SigilGuard.HTTPClient`, the library's only
sanctioned HTTP seam. Configure it per call (`http_client:` in the store options) or in
the application environment:

```elixir
# config/runtime.exs
config :sigil_guard, :http_client, MyApp.AnchorHTTPClient
```

```elixir
defmodule MyApp.AnchorHTTPClient do
  @behaviour SigilGuard.HTTPClient

  @impl true
  def request(method, url, headers, body, opts) do
    # Honor opts[:timeout]; return {:ok, %{status:, headers:, body:}} or
    # {:error, reason}. Retries, if any, live here within the timeout budget.
    MyApp.HTTP.request(method, url, headers, body, timeout: opts[:timeout])
  end
end
```

With no resolvable client the store fails closed with
`:http_client_not_configured` at first use — never a silent no-op.

### Requiring WORM semantics

A WORM store MUST prove the object cannot be overwritten. Pass `require_worm:
true` so the store rejects any receipt unless the remote service explicitly
returns `"worm": true`, and require a signed receipt so the provenance is
verifiable offline:

```elixir
alias SigilGuard.Audit.Anchor.Store

{:ok, receipt} =
  Store.put(Store.HTTP, anchor,
    url: "https://audit.example.internal",
    require_worm: true,
    require_receipt_signature: true,
    receipt_public_key_b64u: worm_service_public_key
  )
```

`Store.fetch/2` reads a record back by receipt or digest and rejects it unless
its canonical digest matches the request; when it falls back to a receipt URI,
private, loopback, and link-local targets are rejected unless
`allow_private_receipt_url: true` is passed. Bodies over `:max_body_bytes`
(default 1 MiB) fail `:response_too_large`.

The remote endpoint contract (paths, request body, receipt shape) is documented
on `SigilGuard.Audit.Anchor.Store.HTTP`; a WORM adapter is that endpoint backed
by object-lock or append-only storage.
