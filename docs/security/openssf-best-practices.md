# OpenSSF Best Practices Evidence Map

Status recorded: 2026-07-07.

BadgeApp project status: no public `bestpractices.dev` project entry was found
for `https://github.com/futhr/sigil_guard` by the project search/API probes.
The passing badge cannot be embedded until a maintainer creates or claims the
project in BadgeApp and obtains the project id.

When the project id exists, add this README badge form:

```markdown
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/<project-id>/badge)](https://www.bestpractices.dev/projects/<project-id>)
```

## Evidence For Passing Criteria

| Area | Project evidence |
|------|------------------|
| Basics | `README.md` describes the project, install flow, API use, feedback path, and contribution path. |
| License | `LICENSE` contains the MIT license; `mix.exs` package metadata identifies repository links. |
| Documentation | `README.md`, ExDoc extras, `guides/`, `notebooks/`, and `docs/specs/` document public use and interfaces. |
| Change Control | Git history is public; `CHANGELOG.md` records release changes; commit rules are documented in `CLAUDE.md`. |
| Reporting | GitHub issues and pull requests are the public bug/enhancement channel; `SECURITY.md` defines private vulnerability reporting. |
| Quality | `.github/workflows/ci.yml` runs formatting, Credo, dependency audit, Sobelow, tests, docs, and Dialyzer gates. |
| Tests | The test tree covers scanner, policy, runtime gate, audit, trust bundle, confirmation, and threat-model paths. |
| Security | `SECURITY.md`, threat-model tests, `mix sobelow`, `mix deps.audit`, no network in core decision paths, and host-owned transport boundaries map to security criteria. |
| Analysis | `mix credo --strict`, `mix dialyzer`, `mix sobelow --config`, and `mix deps.audit` are documented quality gates. |
| Supply chain | `mix sigil_guard.sbom`, release provenance tasks, and SP.05 audit/release provenance docs cover release artifact evidence. |

## Manual BadgeApp Steps

1. Log in to `https://www.bestpractices.dev/` with a maintainer account.
2. Add or claim the project for `https://github.com/futhr/sigil_guard`.
3. Fill the passing-level checklist with the evidence above.
4. Confirm the public project page shows passing status.
5. Add the project-specific badge markdown to `README.md`.
6. Update `docs/tasks/sigil-tasks.md` and mark `M7.18` complete only after the
   public page shows passing.

