defmodule SigilGuard.LLMGuardCompare do
  @moduledoc false

  @corpora ~w(clean_1k.txt clean_64k.txt clean_1m.txt hits_1k.txt hits_64k.txt hits_1m.txt)
  @iterations 10
  @output_json "bench/output/llm_guard_comparison.json"
  @output_md "bench/output/llm_guard_comparison.md"
  @python_json "bench/output/llm_guard_python.json"
  @secret "AKIAIOSFODNN7EXAMPLE"

  @doc false
  def run do
    File.mkdir_p!("bench/output")

    sigil_results = sigil_guard_results()
    python_results = llm_guard_results()

    document = %{
      "schema" => "sigil_guard_llm_guard_comparison/v1",
      "recorded_at" => Date.utc_today() |> Date.to_iso8601(),
      "environment" => environment(python_results["environment"]),
      "scope" => scope(),
      "results" => Map.merge(sigil_results, python_results["results"])
    }

    File.write!(@output_json, Jason.encode!(document, pretty: true))
    File.write!(@output_md, markdown(document))
  end

  defp sigil_guard_results do
    for corpus <- @corpora, into: %{} do
      payload = File.read!(Path.join("bench/corpus", corpus))

      samples =
        for _ <- 1..@iterations do
          {time, _result} = :timer.tc(fn -> SigilGuard.scan(payload) end)
          System.convert_time_unit(time, :microsecond, :nanosecond)
        end

      {"sigil_guard.scan #{corpus}",
       %{
         "corpus" => corpus,
         "path" => "deterministic",
         "median_ns" => median(samples),
         "p99_ns" => Enum.max(samples),
         "verdict" => scan_verdict(payload),
         "synthetic_secret_count" => synthetic_secret_count(payload)
       }}
    end
  end

  defp llm_guard_results do
    {output, status} =
      System.cmd(
        "uv",
        [
          "run",
          "--python",
          "3.11",
          "--with",
          "llm-guard",
          "python",
          "bench/llm_guard_compare.py",
          "--iterations",
          Integer.to_string(@iterations),
          "--output",
          @python_json
        ],
        stderr_to_stdout: true
      )

    if status != 0 do
      raise "llm-guard comparison failed with status #{status}:\n#{output}"
    end

    @python_json
    |> File.read!()
    |> Jason.decode!()
  end

  defp scan_verdict(payload) do
    case SigilGuard.scan(payload) do
      {:ok, _} -> "clean"
      {:hit, hits} -> "hit:#{length(hits)}"
    end
  end

  defp synthetic_secret_count(payload) do
    Regex.scan(~r/#{@secret}/, payload) |> length()
  end

  defp median(samples) do
    samples
    |> Enum.sort()
    |> Enum.at(div(length(samples), 2))
  end

  defp environment(python_environment) do
    %{
      "hardware" => cpu_info(),
      "cores" => System.schedulers_online(),
      "os" => os_info(),
      "elixir" => System.version(),
      "otp" => System.otp_release(),
      "sigil_guard" => "#{Application.spec(:sigil_guard, :vsn)} (#{git_commit()})",
      "python" => python_environment["python"],
      "llm_guard" => python_environment["llm_guard"],
      "llm_guard_scanners" => python_environment["scanners"],
      "iterations" => @iterations,
      "date" => Date.utc_today() |> Date.to_iso8601()
    }
  end

  defp scope do
    %{
      "corpus" => "bench/corpus clean_* and hits_* text fixtures",
      "comparison" => "SigilGuard.scan/1 versus llm-guard input scanners only",
      "paths" => %{
        "deterministic" => [
          "SigilGuard.scan/1 built-in deterministic scanner",
          "llm_guard.input_scanners.secrets.Secrets",
          "llm_guard.input_scanners.regex.Regex configured for AKIA access keys"
        ],
        "ml" =>
          "not measured; prompt-injection classifiers are outside this synthetic secret-scanning corpus"
      }
    }
  end

  defp markdown(document) do
    """
    # SigilGuard / llm-guard Scanner-Scope Comparison

    Values are measured for this environment, not ratified SLO bounds.

    ## Environment

    - Hardware: #{document["environment"]["hardware"]}, #{document["environment"]["cores"]} cores
    - OS: #{document["environment"]["os"]}
    - Elixir: #{document["environment"]["elixir"]} / OTP: #{document["environment"]["otp"]}
    - SigilGuard: #{document["environment"]["sigil_guard"]}
    - Python: #{document["environment"]["python"]}
    - llm-guard: #{document["environment"]["llm_guard"]}
    - Iterations per row: #{document["environment"]["iterations"]}
    - Date: #{document["environment"]["date"]}

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
    #{result_rows(document["results"])}
    """
  end

  defp result_rows(results) do
    results
    |> Enum.sort_by(fn {name, _} -> name end)
    |> Enum.map_join("\n", fn {name, row} ->
      signal = row["verdict"] || "valid=#{row["valid"]}; score_max=#{row["score_max"]}"

      "| #{name} | #{row["corpus"]} | #{row["path"]} | #{row["median_ns"]} | #{row["p99_ns"]} | #{signal} |"
    end)
  end

  defp cpu_info do
    case System.cmd("sysctl", ["-n", "machdep.cpu.brand_string"], stderr_to_stdout: true) do
      {cpu, 0} -> String.trim(cpu)
      _ -> inspect(:erlang.system_info(:cpu_topology), limit: 8)
    end
  end

  defp os_info do
    {family, name} = :os.type()
    "#{family}/#{name}"
  end

  defp git_commit do
    case System.cmd("git", ["rev-parse", "--short", "HEAD"], stderr_to_stdout: true) do
      {commit, 0} -> String.trim(commit)
      _ -> "unknown"
    end
  end
end

SigilGuard.LLMGuardCompare.run()
