---
name: done
description: Run SigilGuard's full quality gate after implementation, docs changes, or before committing. Use when work is finished, ready to commit, ship-ready, or whenever the user asks for clean gates.
allowed-tools: Bash(mix *), Bash(git *), Bash(rg *)
---

# Done - SigilGuard Quality Gate

Run gates from `CLAUDE.md` and stop at the first failure. Fix the root cause,
rerun the failed gate, then continue.

## Required Gates

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
./bin/check
```

Also run the local forbidden inspiration-project term scan without committing
the literal terms to repo text. Run the local dead public protocol/registry URL
scan the same way.

## Pass Criteria

- All commands exit 0.
- Coverage remains at or above 95%.
- No dead public protocol/registry URLs are present.
- No AI attribution is added to commits.
