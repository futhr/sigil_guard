---
sigil_guard:
  template_type: task
  template_version: "1.0.0"
---

# [Project] Tasks

## Progress Summary

| Category | Total | Complete | In Progress | Planned |
|----------|-------|----------|-------------|---------|
| [Category] | [N] | [N] | [N] | [N] |
| **Total** | **[N]** | **[N]** | **[N]** | **[N]** |

## Quality Gates

- [ ] `git diff --check`.
- [ ] No forbidden project-inspiration terms.
- [ ] No dead public SIGIL URLs.
- [ ] `mix format --check-formatted`.
- [ ] `mix compile --warnings-as-errors`.
- [ ] `mix credo --strict`.
- [ ] `mix sobelow --config --compact`.
- [ ] `mix deps.audit`.
- [ ] `mix test --cover` with coverage >= 95%.
- [ ] `mix doctor`.
- [ ] `mix dialyzer`.
- [ ] `mix docs`.
- [ ] `./bin/check`.

## [SPEC-ID] - [Task Title]

> References: `docs/specs/[SPEC-ID]-[slug].md`
> Effort: [XS | S | M | L | XL]
> Status: [planned | in-progress | complete]
> Dependencies: [list]

### Description

[One or two sentences.]

### Acceptance Criteria

- [ ] [Specific, testable criterion].
- [ ] Tests cover happy, tamper, malformed, replay/expiry where relevant.
- [ ] All quality gates pass.

### Implementation Steps

- [ ] [Step 1].
- [ ] [Step 2].
- [ ] [Step 3].
