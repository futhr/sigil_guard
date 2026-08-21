---
name: sigil-spec
description: "Apply automatically when authoring or revising a SigilGuard implementation spec under docs/specs. Define observable trust-profile, digest, bundle, MCP, scanner, policy, audit, replay, expiry, and compatibility behavior, including negative cases and unresolved authority decisions, before code changes begin."
---

# Sigil Spec

Specs live under `docs/specs/` and use
`docs/templates/spec-base.md`.

Write only under `docs/specs/` and `docs/tasks/sigil-tasks.md`. Do not modify
source, tests, config, or quality-ignore files from this skill.

## Required Sections

- Executive summary.
- Business value.
- Data flow with Mermaid when the design crosses modules.
- Data model or explicit "No new data model".
- Module map with real file paths.
- Error handling.
- Security considerations.
- Testing strategy.
- Implementation roadmap.
- Sources.

## Constraints

- Keep SigilGuard embedded/local-first.
- Treat old protocol names as compatibility contracts only.
- Preserve current public APIs unless the spec explicitly marks a future
  breaking change.
- Add or update `docs/tasks/sigil-tasks.md` when the spec creates work.
