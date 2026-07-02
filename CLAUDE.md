# CLAUDE.md - SigilGuard

IMPORTANT: SigilGuard is a native Elixir Hex library for embedded MCP and
agent-tool security. It is not a hosted registry product, not a SaaS control
plane, and not a Rust/NIF wrapper. Host applications own their transports,
authentication systems, and deployment model; SigilGuard provides verification,
policy, scanning, audit, vault, and trust-bundle primitives they can embed.

## Hard Rules

1. No Rust or NIF backend work. The native Elixir backend is the only supported
   built-in backend.
2. Do not depend on the old upstream project, public service, or hosted
   registry. `sigil` remains the project name and idiom; old material is historical
   inspiration and compatibility context only.
3. Preserve consumer-facing contracts within the 0.2.x line. V3 is the
   deliberate, spec-governed breaking release: `_sigil`, `_sigil_confirmation`,
   profile names, and envelope shapes are replaced by the Agent Trust surfaces
   in `SP.01`-`SP.05` and `SP.13`. Every removal must follow the migration
   mapping destined for `MIGRATING-3.0.md`. No ad hoc breaks, no permanent
   compatibility shims.
4. Default trust material is embedded and local. Remote fetch is host-owned;
   the v3 core performs no HTTP. The only sanctioned HTTP seam is the
   host-provided `SigilGuard.HTTPClient` behaviour used by audit anchor
   stores (`SP.05`). The v2 registry adapter stays an explicit, signed
   compatibility adapter until its removal in v3 (`SP.12`).
5. Boundary awareness is mandatory for runtime security work. Every tool or MCP
   decision should account for phase, origin, sink, actor/identity, trust zone,
   action digest, payload digest, and policy verdict.
6. Every public API must have `@doc` and `@spec`. Complex structs need typedocs.
7. No `String.to_atom/1` on external input. Use closed maps or
   `String.to_existing_atom/1` only when the atom set is already known.
8. Do not add remote network calls to core decision paths unless a spec explains
   the trust, timeout, retry, and failure model.
9. Keep test coverage at or above 95%. New security modules need negative,
   tamper, replay, expiration, and malformed-input tests.
10. Never add AI attribution, co-author trailers, or generated-by comments to
    commits or source files.
11. Never write the name of the private consumer project, or its internal
    module names, into any repository file (source, docs, comments, tests,
    fixtures, commits). Refer to the production consumer only as "the
    reference consumer". See the Orientation section of
    `docs/tasks/sigil-tasks.md`.

## Current Architecture

```
SigilGuard public API
  -> native Elixir backend
  -> Scanner / Runtime Gate / MCP Gateway / Confirmation / Envelope
  -> Policy / RepoPolicy / Audit / Vault / Trust-bundle compatibility path
```

The `SigilGuard.Registry` namespace is legacy naming. It remains in the 0.2.x
line because the current public API and tests use it; v3 removes it per
`docs/specs/SP.12-legacy-remote-bundle-adapter-contracts.md`. New work uses
the terminology defined in `docs/specs/SP.01-sigilguard-trust-profile.md`.
V3 keeps a minimal, individually justified runtime dependency set
(`:telemetry`, `:nimble_options`, `:jason`), an Elixir `~> 1.18` floor, and
no network in core decision paths; finch leaves with the registry, and audit
anchor HTTP goes through a host-provided `SigilGuard.HTTPClient` behaviour.

## Documentation System

- `docs/research/` - research notes with sources, methodology, alternatives,
  and decisions.
- `docs/specs/` - implementable specs for trust-profile work.
- `docs/tasks/sigil-tasks.md` - canonical checkbox task list.
- `docs/templates/` - templates for future research, specs, and tasks.
- `.claude/skills/` - repo-specific workflows for Claude Code.
- `.claude/standards/` - stable engineering standards.

## Quality Gates

Before committing or handing off after a code or doc change, run:

```bash
git diff --check
mix format --check-formatted
mix compile --warnings-as-errors
mix credo --strict
mix sobelow --config --compact
mix deps.audit
mix test --cover
mix doctor
mix dialyzer
mix docs
mix check --no-retry
```

Also run local scans for forbidden inspiration-project terms and dead public
protocol/registry URLs without committing those literal strings to repo text.

`mix check --no-retry` is the repo-level gate. The individual commands make
failures easier to diagnose. All gates must be clean.

## Commit Rules

Use Conventional Commits:

- `feat(scope): description`
- `fix(scope): description`
- `docs(scope): description`
- `test(scope): description`
- `refactor(scope): description`
- `chore(scope): description`

Do not include `Co-Authored-By` or AI attribution.

## Research And Spec Discipline

Do research before protocol/security design. Prefer primary sources: MCP
specifications, RFCs, OWASP, NIST/NSA guidance, TUF/SLSA/Sigstore specs, W3C
DID/VC specs, and source repositories. Each accepted design needs a spec and a
task entry before broad implementation.
