# Compare the audited implementation and current code in the same BEAM instance.
# The baseline ref is explicit so the experiment remains reproducible after commits.
[baseline_ref] = System.argv()

for {path, original, renamed} <- [
      {"lib/sigil_guard/scanner.ex", "SigilGuard.Scanner", "SigilGuard.BenchmarkBaselineScanner"},
      {"lib/sigil_guard/scanner/pipeline.ex", "SigilGuard.Scanner.Pipeline",
       "SigilGuard.BenchmarkBaselinePipeline"}
    ] do
  {source, 0} = System.cmd("git", ["show", "#{baseline_ref}:#{path}"])

  source =
    String.replace(source, "defmodule #{original} do", "defmodule #{renamed} do", global: false)

  Code.compile_string(source)
end

text = String.duplicate("safe AKIAIOSFODNN7EXAMPLE tail\n", 1_000)
{:hit, hits} = SigilGuard.Scanner.scan(text)
patterns = SigilGuard.Patterns.built_in()
synthetic_value = Base.encode16(:crypto.hash(:sha256, "sigil-benchmark-token"), case: :lower)
pipeline_text = String.duplicate("api_key=" <> synthetic_value <> "\n", 1_000)

suite =
  Benchee.run(
    %{
      "redaction baseline" => fn -> SigilGuard.BenchmarkBaselineScanner.redact(text, hits) end,
      "redaction current" => fn -> SigilGuard.Scanner.redact(text, hits) end,
      "pipeline baseline" => fn ->
        SigilGuard.BenchmarkBaselinePipeline.scan(pipeline_text, patterns)
      end,
      "pipeline current" => fn -> SigilGuard.Scanner.Pipeline.scan(pipeline_text, patterns) end
    },
    warmup: 1,
    time: 3,
    memory_time: 1,
    print: [fast_warning: false]
  )

results =
  Map.new(suite.scenarios, fn scenario ->
    {scenario.name,
     %{
       median_ns: scenario.run_time_data.statistics.median,
       memory_bytes: scenario.memory_usage_data.statistics.median
     }}
  end)

File.write!(
  "bench/output/audit-remediation.json",
  Jason.encode!(
    %{
      baseline_ref: baseline_ref,
      elixir: System.version(),
      otp: System.otp_release(),
      results: results
    },
    pretty: true
  )
)
