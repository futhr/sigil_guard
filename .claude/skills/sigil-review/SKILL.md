---
name: sigil-review
description: "Apply automatically when SigilGuard work involving trust profiles, policy, canonical digests, replay/expiry, bundles, MCP effects, and v3 compatibility needs review sigilguard changes for security, compatibility, tests, docs, ai-slop/test-integrity signals, and quality-gate risk. use when the user asks for review, audit, bug hunt, coverage review, or architecture review. Use repository evidence, preserve authority boundaries, and report blocked or unavailable proof explicitly."
---

# Sigil Review

Review in this order:

1. Security bugs and trust-boundary failures.
2. Compatibility regressions in existing public contracts.
3. Missing tamper/malformed/replay/expiry tests.
4. Coverage and quality-gate risk.
5. AI-slop and test-integrity risk.
6. Documentation drift against research/spec/task files.

Findings should include file and line references. If no issue is found, say so
and name the remaining test or operational risk.

## Extra Checks

- No public registry default.
- No dead protocol/registry URLs.
- No Rust/NIF reintroduction.
- No remote network trust in core decision paths without a spec.
- No dynamic atom creation from external input.
- Credo nesting max is 2. Refactor with pattern matching, small helpers, or
  guard clauses; do not add Credo excludes/disable comments to pass.
- No generated-by/co-author markers, pointless comments, coverage padding,
  broad skip/exclude blocks, or tests that merely execute code without
  asserting behavior.
- Library posture: no surprising app startup, hidden global app-env dependency,
  network/process/clock side effects in pure APIs, or avoidable runtime deps.
  Host-owned side effects must stay behind behaviours/options.
- Treat AI-origin signals as weak provenance evidence, not proof. Report
  concrete quality issues with `file:line` and the smallest fix.
