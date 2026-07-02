---
name: sigil-implement
description: Implement a SigilGuard task from docs/tasks/sigil-tasks.md or docs/specs. Use for code changes in trust profile, bundles, MCP gateway, scanner, policy, audit, or docs-backed feature work.
allowed-tools: Bash(mix *), Bash(rg *), Bash(git *)
---

# Sigil Implement

Before editing:

1. Read the referenced spec.
2. Read the current module and tests.
3. Confirm the task preserves embedded/local-first trust.
4. Identify compatibility contracts that must not change.

During implementation:

- Keep changes scoped to the spec.
- Add tests with the behavior change.
- Include tamper, malformed, expiry, replay, or quarantine tests for security
  surfaces.
- Prefer behaviours and plain data structs over process state unless the spec
  requires OTP ownership.

After implementation:

- Update `docs/tasks/sigil-tasks.md`.
- Run the focused tests first.
- Run the `done` skill before committing.
