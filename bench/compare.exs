defmodule SigilGuard.BenchCompare do
  @moduledoc false

  @schema "sigil_guard_bench_baseline/v1"
  @threshold 0.20
  @runner_keys ~w(hardware cores os elixir otp benchee)
  @stat_keys ~w(median_ns p99_ns memory_bytes)

  @type finding ::
          {:fail, String.t()}
          | {:warn, String.t()}
          | {:pass, String.t()}

  @doc false
  def main(argv \\ System.argv()) do
    opts = parse_args(argv)

    baseline = read_json!(opts.baseline)
    run = read_json!(opts.run)

    case compare(baseline, run) do
      {:ok, findings} ->
        print_findings(findings)
        :ok

      {:error, findings} ->
        print_findings(findings)
        System.halt(1)
    end
  end

  @doc false
  def compare(baseline, run) when is_map(baseline) and is_map(run) do
    with :ok <- validate_document(baseline, "baseline"),
         :ok <- validate_document(run, "run") do
      compare_valid(baseline, run)
    else
      {:error, reason} -> {:error, [{:fail, reason}]}
    end
  end

  def compare(_, _), do: {:error, [{:fail, "benchmark documents must be JSON objects"}]}

  @doc false
  def validate_document(document, label) do
    with :ok <- require_field(document, "schema", label),
         :ok <- require_field(document, "environment", label),
         :ok <- require_field(document, "recorded_at", label),
         :ok <- require_field(document, "scenarios", label),
         :ok <- require_schema(document, label),
         :ok <- require_environment(document["environment"], label),
         :ok <- require_recorded_at(document["recorded_at"], label),
         :ok <- require_scenarios(document["scenarios"], label) do
      :ok
    end
  end

  defp compare_valid(baseline, run) do
    if runner_class(baseline) == runner_class(run) do
      binding_compare(baseline["scenarios"], run["scenarios"])
    else
      {:ok,
       [
         {:warn,
          "runner class differs from baseline; comparison is informational and does not fail"}
       ]}
    end
  end

  defp binding_compare(baseline_scenarios, run_scenarios) do
    missing =
      baseline_scenarios
      |> Map.keys()
      |> Enum.reject(&Map.has_key?(run_scenarios, &1))
      |> Enum.map(&{:fail, "missing run scenario: #{&1}"})

    regressions =
      baseline_scenarios
      |> Enum.flat_map(fn {name, baseline_stats} ->
        case Map.fetch(run_scenarios, name) do
          {:ok, run_stats} -> regression_findings(name, baseline_stats, run_stats)
          :error -> []
        end
      end)

    new_scenarios =
      run_scenarios
      |> Map.keys()
      |> Enum.reject(&Map.has_key?(baseline_scenarios, &1))
      |> Enum.map(&{:warn, "new scenario without baseline: #{&1}"})

    findings = missing ++ regressions ++ new_scenarios

    if Enum.any?(findings, &match?({:fail, _}, &1)) do
      {:error, findings}
    else
      {:ok, pass_if_empty(findings)}
    end
  end

  defp regression_findings(name, baseline_stats, run_stats) do
    baseline_median = baseline_stats["median_ns"]
    run_median = run_stats["median_ns"]

    if run_median > baseline_median * (1 + @threshold) do
      [
        {:fail,
         "#{name} median regressed by #{percent(run_median, baseline_median)} " <>
           "(#{run_median} ns vs #{baseline_median} ns)"}
      ]
    else
      []
    end
  end

  defp pass_if_empty([]), do: [{:pass, "no binding benchmark regressions"}]
  defp pass_if_empty(findings), do: findings

  defp percent(run, baseline) when baseline > 0 do
    ((run - baseline) / baseline * 100)
    |> Float.round(1)
    |> then(&"#{&1}%")
  end

  defp runner_class(document) do
    Map.take(document["environment"], @runner_keys)
  end

  defp require_field(document, field, label) do
    if Map.has_key?(document, field), do: :ok, else: {:error, "#{label} missing #{field}"}
  end

  defp require_schema(%{"schema" => @schema}, _), do: :ok
  defp require_schema(_, label), do: {:error, "#{label} has unsupported schema"}

  defp require_environment(environment, label) when is_map(environment) do
    missing = Enum.reject(@runner_keys ++ ["date", "sigil_guard"], &Map.has_key?(environment, &1))

    case missing do
      [] -> :ok
      _ -> {:error, "#{label} environment missing #{Enum.join(missing, ", ")}"}
    end
  end

  defp require_environment(_, label), do: {:error, "#{label} environment must be an object"}

  defp require_recorded_at(date, _label) when is_binary(date) do
    case Date.from_iso8601(date) do
      {:ok, _} -> :ok
      {:error, _} -> {:error, "recorded_at must be an ISO 8601 date"}
    end
  end

  defp require_recorded_at(_, _label), do: {:error, "recorded_at must be a string"}

  defp require_scenarios(scenarios, label) when is_map(scenarios) and map_size(scenarios) > 0 do
    scenarios
    |> Enum.find_value(:ok, fn {name, stats} -> validate_stats(name, stats, label) end)
  end

  defp require_scenarios(_, label), do: {:error, "#{label} scenarios must be a non-empty object"}

  defp validate_stats(name, stats, label) when is_binary(name) and is_map(stats) do
    cond do
      missing_stat = Enum.find(@stat_keys, &(not Map.has_key?(stats, &1))) ->
        {:error, "#{label} scenario #{name} missing #{missing_stat}"}

      Enum.any?(@stat_keys, &(not non_negative_integer?(stats[&1]))) ->
        {:error, "#{label} scenario #{name} has invalid numeric statistics"}

      true ->
        false
    end
  end

  defp validate_stats(_, _, label), do: {:error, "#{label} scenario entries are invalid"}

  defp non_negative_integer?(value), do: is_integer(value) and value >= 0

  defp read_json!(path) do
    path
    |> File.read!()
    |> Jason.decode!()
  end

  defp parse_args(argv) do
    {opts, _argv, invalid} =
      OptionParser.parse(argv,
        strict: [baseline: :string, run: :string],
        aliases: [b: :baseline, r: :run]
      )

    if invalid != [] do
      raise ArgumentError, "invalid options: #{inspect(invalid)}"
    end

    %{
      baseline: Keyword.get(opts, :baseline, "bench/baseline.json"),
      run: Keyword.get(opts, :run, "bench/output/benchmarks.json")
    }
  end

  defp print_findings(findings) do
    Enum.each(findings, fn
      {:pass, message} -> IO.puts("PASS: #{message}")
      {:warn, message} -> IO.puts("WARN: #{message}")
      {:fail, message} -> IO.puts("FAIL: #{message}")
    end)
  end
end

unless function_exported?(Mix, :env, 0) and Mix.env() == :test do
  SigilGuard.BenchCompare.main()
end
