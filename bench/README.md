# SigilGuard Benchmarks

This directory holds the reproducible benchmark harness. The methodology and
fairness rules it implements are specified under `docs/specs/` in the source
repository.

## Commands

```bash
mix run bench/corpus.exs
mix bench --smoke
mix bench
mix run bench/compare.exs
```

`mix bench --smoke` exercises every BM.01-BM.08 scenario with tiny timing
budgets for CI. `mix bench` uses the published measurement settings:
`warmup: 2`, `time: 5`, and `memory_time: 2`.

## Baseline Refresh

Refresh `bench/baseline.json` only in a dedicated PR. Run the full matrix
three times on the same runner class and confirm every scenario median is
within +/-5% across the three runs. Then copy the accepted
`bench/output/benchmarks.json` to `bench/baseline.json`.

The commit message must state why the baseline changed: accepted performance
change, runner change, or Elixir/OTP bump. Silent baseline edits are treated
as masking a regression.
