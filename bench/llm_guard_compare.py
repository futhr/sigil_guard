import argparse
import contextlib
import importlib.metadata
import io
import json
import platform
import re
import statistics
import time
from pathlib import Path

from llm_guard.input_scanners.regex import Regex
from llm_guard.input_scanners.secrets import Secrets


CORPORA = [
    "clean_1k.txt",
    "clean_64k.txt",
    "clean_1m.txt",
    "hits_1k.txt",
    "hits_64k.txt",
    "hits_1m.txt",
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    results = {
        "environment": {
            "python": platform.python_version(),
            "llm_guard": importlib.metadata.version("llm-guard"),
            "scanners": {
                "llm_guard.secrets": {
                    "path": "deterministic",
                    "class": "llm_guard.input_scanners.secrets.Secrets",
                    "configuration": {"redact_mode": "all"},
                },
                "llm_guard.regex.aws_access_key": {
                    "path": "deterministic",
                    "class": "llm_guard.input_scanners.regex.Regex",
                    "configuration": {
                        "patterns": ["AKIA[0-9A-Z]{16}"],
                        "redact": True,
                        "is_blocked": True,
                    },
                },
            },
        },
        "results": {},
    }

    scanners = {
        "llm_guard.secrets": lambda: Secrets(redact_mode="all"),
        "llm_guard.regex.aws_access_key": lambda: Regex([r"AKIA[0-9A-Z]{16}"]),
    }

    for corpus in CORPORA:
        payload = Path("bench/corpus", corpus).read_text()

        for scanner_name, scanner_factory in scanners.items():
            scanner = scanner_factory()
            samples = []
            valid_values = []
            scores = []

            for _ in range(args.iterations):
                started = time.perf_counter_ns()

                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    _sanitized, valid, score = scanner.scan(payload)

                samples.append(time.perf_counter_ns() - started)
                valid_values.append(valid)
                scores.append(score)

            results["results"][f"{scanner_name} {corpus}"] = {
                "corpus": corpus,
                "path": results["environment"]["scanners"][scanner_name]["path"],
                "median_ns": round(statistics.median(samples)),
                "p99_ns": round(max(samples)),
                "valid": all(valid_values),
                "score_max": max(scores),
                "synthetic_secret_count": len(re.findall(r"AKIAIOSFODNN7EXAMPLE", payload)),
            }

    Path(args.output).write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
