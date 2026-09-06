# SigilGuard Quality Gates

Run these before handoff or commit:

```bash
git diff --check
mix format --check-formatted
mix compile --warnings-as-errors
mix credo --strict
mix sobelow --config --compact
./bin/check-secrets
mix deps.audit
mix hex.audit
mix test --cover
./bin/check-verdict-mutations
mix sigil.livebook_check
mix doctor
mix dialyzer
mix docs
./bin/check
```

`./bin/check` is the canonical clean-clone entry point. It fetches the locked
dependencies before invoking ExCheck without retries.

Also run local scans for forbidden inspiration-project terms and dead public
protocol/registry URLs without committing those literal strings to repo text.

Coverage must stay at or above 95%.

Security work also needs focused tests for:

- malformed input.
- tampering.
- replay.
- expiry.
- quarantine.
- compatibility behavior.
