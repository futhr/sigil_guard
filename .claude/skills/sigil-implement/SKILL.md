---
name: sigil-implement
description: "Apply automatically when delivering a bounded SigilGuard task that changes trust profiles, canonical digests, bundles, MCP gateway behavior, scanning, policy enforcement, audit records, or v3 compatibility. Follow the linked task/spec, preserve replay, expiry, confirmation, and authority invariants, and prove affected behavior."
---

# Sigil Implement

Before editing:

1. Read the referenced spec.
2. Read the current module and tests.
3. Confirm the task preserves embedded/local-first trust.
4. Identify compatibility contracts that must not change.

During implementation:

- Keep changes scoped to the spec.
- Do not add coverage skips, broad excludes, generated-by markers, or comments
  that restate code.
- Add tests with the behavior change.
- Include tamper, malformed, expiry, replay, or quarantine tests for security
  surfaces.
- Prefer behaviours and plain data structs over process state unless the spec
  requires OTP ownership.

After implementation:

- Update `docs/tasks/sigil-tasks.md`.
- Run the focused tests first.
- Run the `done` skill before committing.
