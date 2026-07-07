# SigilGuard / llm-guard Scanner-Scope Comparison

Values are measured for this environment, not ratified SLO bounds.

## Environment

- Hardware: Apple M4 Max, 16 cores
- OS: unix/darwin
- Elixir: 1.20.2 / OTP: 29
- SigilGuard: 1.0.0 (298d787)
- Python: 3.11.15
- llm-guard: 0.3.16
- Iterations per row: 10
- Date: 2026-07-07

## Scope

This comparison is scanner-scope only: `SigilGuard.scan/1` is compared
against llm-guard input scanners on the same committed corpus files in
`bench/corpus/`. Gate, attestation, bundle, audit, and policy timings are
excluded because llm-guard has no counterpart surface.

Deterministic paths are labeled `deterministic`. ML paths are not measured
here because the corpus is synthetic secret-scanning text, not a
prompt-injection classification corpus.

## Results

| Scanner | Corpus | Path | Median ns | p99 ns | Signal |
|---------|--------|------|----------:|-------:|--------|
| llm_guard.regex.aws_access_key clean_1k.txt | clean_1k.txt | deterministic | 9416 | 20708 | valid=true; score_max=-1.0 |
| llm_guard.regex.aws_access_key clean_1m.txt | clean_1m.txt | deterministic | 155958 | 170500 | valid=true; score_max=-1.0 |
| llm_guard.regex.aws_access_key clean_64k.txt | clean_64k.txt | deterministic | 18812 | 32458 | valid=true; score_max=-1.0 |
| llm_guard.regex.aws_access_key hits_1k.txt | hits_1k.txt | deterministic | 8729 | 16375 | valid=true; score_max=-1.0 |
| llm_guard.regex.aws_access_key hits_1m.txt | hits_1m.txt | deterministic | 8695520 | 8817750 | valid=false; score_max=1.0 |
| llm_guard.regex.aws_access_key hits_64k.txt | hits_64k.txt | deterministic | 69042 | 116500 | valid=false; score_max=1.0 |
| llm_guard.secrets clean_1k.txt | clean_1k.txt | deterministic | 2093646 | 30659292 | valid=true; score_max=-1.0 |
| llm_guard.secrets clean_1m.txt | clean_1m.txt | deterministic | 18526083 | 19513667 | valid=true; score_max=-1.0 |
| llm_guard.secrets clean_64k.txt | clean_64k.txt | deterministic | 115147083 | 118557250 | valid=true; score_max=-1.0 |
| llm_guard.secrets hits_1k.txt | hits_1k.txt | deterministic | 2082688 | 2280875 | valid=true; score_max=-1.0 |
| llm_guard.secrets hits_1m.txt | hits_1m.txt | deterministic | 17703834 | 18609958 | valid=true; score_max=-1.0 |
| llm_guard.secrets hits_64k.txt | hits_64k.txt | deterministic | 116777417 | 119840000 | valid=false; score_max=1.0 |
| sigil_guard.scan clean_1k.txt | clean_1k.txt | deterministic | 18000 | 3976000 | clean |
| sigil_guard.scan clean_1m.txt | clean_1m.txt | deterministic | 13310000 | 13795000 | clean |
| sigil_guard.scan clean_64k.txt | clean_64k.txt | deterministic | 872000 | 946000 | clean |
| sigil_guard.scan hits_1k.txt | hits_1k.txt | deterministic | 21000 | 51000 | clean |
| sigil_guard.scan hits_1m.txt | hits_1m.txt | deterministic | 14801000 | 16040000 | hit:256 |
| sigil_guard.scan hits_64k.txt | hits_64k.txt | deterministic | 930000 | 1797000 | hit:16 |
