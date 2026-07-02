---
name: sigil-review
description: Review SigilGuard changes for security, compatibility, tests, docs, and quality-gate risk. Use when the user asks for review, audit, bug hunt, coverage review, or architecture review.
allowed-tools: Bash(rg *), Bash(mix *), Bash(git *)
---

# Sigil Review

Review in this order:

1. Security bugs and trust-boundary failures.
2. Compatibility regressions in existing public contracts.
3. Missing tamper/malformed/replay/expiry tests.
4. Coverage and quality-gate risk.
5. Documentation drift against research/spec/task files.

Findings should include file and line references. If no issue is found, say so
and name the remaining test or operational risk.

## Extra Checks

- No public registry default.
- No dead protocol/registry URLs.
- No Rust/NIF reintroduction.
- No remote network trust in core decision paths without a spec.
- No dynamic atom creation from external input.
