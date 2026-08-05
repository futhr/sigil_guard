---
name: sigil-research
description: Create or update SigilGuard research notes under docs/research with primary sources, tradeoff analysis, and an explicit decision. Use for protocol, MCP, trust-bundle, audit, scanner, or security design research.
disable-model-invocation: true
allowed-tools: Read, Glob, Grep, Edit, Write, Bash(rg *), Bash(sed *), WebSearch, WebFetch
---

# Sigil Research

Research belongs in `docs/research/R.NNN-topic.md` using
`docs/templates/research-base.md`.

Write only under `docs/research/`. Do not modify source, tests, config, or
quality-ignore files from this skill.

## Rules

- Prefer primary sources: MCP specs, RFCs, OWASP, W3C, TUF, SLSA, Sigstore,
  in-toto, NIST/NSA, and upstream source repositories.
- Identify whether evidence supports embedded/local trust, optional internal
  HTTP compatibility, or a rejected public discovery model.
- Separate facts, inference, and recommendation.
- End with impact on modules, specs, migration, and breaking changes.
- Do not introduce direct integration with inspiration projects outside this
  repo.

## Output

Create or update one research note and list the specs/tasks it affects.
