defmodule SigilGuard.BenchCompareTest do
  @moduledoc false

  use ExUnit.Case, async: true

  Code.require_file("../../bench/compare.exs", __DIR__)

  @scenario "BM.01 scan clean 1k"

  test "25 percent median regression fails on a matching runner class" do
    baseline = document(median_ns: 100)
    run = document(median_ns: 125)

    assert {:error, [{:fail, message}]} = SigilGuard.BenchCompare.compare(baseline, run)
    assert message =~ "regressed by 25.0%"
  end

  test "15 percent median regression passes on a matching runner class" do
    baseline = document(median_ns: 100)
    run = document(median_ns: 115)

    assert {:ok, [{:pass, "no binding benchmark regressions"}]} =
             SigilGuard.BenchCompare.compare(baseline, run)
  end

  test "missing baseline scenario in the run fails" do
    baseline = document()
    run = put_in(document(), ["scenarios"], %{"BM.02 scan hits 1k" => stats(median_ns: 100)})

    assert {:error, findings} = SigilGuard.BenchCompare.compare(baseline, run)
    assert {:fail, "missing run scenario: " <> @scenario} in findings
  end

  test "new run scenarios pass with a warning" do
    baseline = document()

    run =
      document()
      |> put_in(["scenarios", "BM.99 new scenario"], stats(median_ns: 1))

    assert {:ok, [{:warn, "new scenario without baseline: BM.99 new scenario"}]} =
             SigilGuard.BenchCompare.compare(baseline, run)
  end

  test "runner class mismatch is informational" do
    baseline = document(median_ns: 100)
    run = document(median_ns: 10_000) |> put_in(["environment", "hardware"], "different")

    assert {:ok, [{:warn, message}]} = SigilGuard.BenchCompare.compare(baseline, run)
    assert message =~ "runner class differs"
  end

  test "smoke run validates the benchmark matrix without median regression checks" do
    baseline = document(median_ns: 100)
    run = document(mode: "smoke", median_ns: 10_000)

    assert {:ok, [{:pass, "smoke benchmark matrix matches baseline"}]} =
             SigilGuard.BenchCompare.compare(baseline, run)
  end

  test "smoke run still fails when a baseline scenario is missing" do
    baseline = document()

    run =
      document(mode: "smoke")
      |> put_in(["scenarios"], %{"BM.99 new scenario" => stats(median_ns: 1)})

    assert {:error, findings} = SigilGuard.BenchCompare.compare(baseline, run)
    assert {:fail, "missing run scenario: " <> @scenario} in findings
  end

  test "invalid benchmark mode fails validation" do
    assert {:error, message} =
             document(mode: "partial")
             |> SigilGuard.BenchCompare.validate_document("run")

    assert message == "run mode must be measured or smoke"
  end

  test "committed baseline and latest output satisfy the data model" do
    for path <- ["bench/baseline.json", "bench/output/benchmarks.json"] do
      document =
        path
        |> File.read!()
        |> Jason.decode!()

      assert :ok = SigilGuard.BenchCompare.validate_document(document, path)
    end
  end

  test "llm-guard comparison artifact is scanner-scope and labeled" do
    document =
      "bench/output/llm_guard_comparison.json"
      |> File.read!()
      |> Jason.decode!()

    assert document["schema"] == "sigil_guard_llm_guard_comparison/v1"
    assert document["environment"]["llm_guard"] =~ ~r/^\d+\.\d+\.\d+/
    assert document["scope"]["comparison"] =~ "SigilGuard.scan/1 versus llm-guard input scanners"
    assert document["scope"]["paths"]["ml"] =~ "not measured"

    result_names = Map.keys(document["results"])
    assert Enum.any?(result_names, &String.starts_with?(&1, "sigil_guard.scan "))
    assert Enum.any?(result_names, &String.starts_with?(&1, "llm_guard."))
    refute Enum.any?(result_names, &String.contains?(&1, "gate"))
    refute Enum.any?(result_names, &String.contains?(&1, "attestation"))

    assert Enum.all?(document["results"], fn {_, result} ->
             result["path"] == "deterministic" and String.ends_with?(result["corpus"], ".txt")
           end)
  end

  defp document(overrides \\ []) do
    mode = Keyword.get(overrides, :mode)
    stats_overrides = Keyword.drop(overrides, [:mode])

    document = %{
      "schema" => "sigil_guard_bench_baseline/v1",
      "environment" => %{
        "hardware" => "runner",
        "cores" => 8,
        "os" => "unix/linux",
        "elixir" => "1.20.0",
        "otp" => "29",
        "benchee" => "warmup 2 s, time 5 s, memory_time 2 s",
        "date" => "2026-07-07",
        "sigil_guard" => "1.0.0 (abc123)"
      },
      "recorded_at" => "2026-07-07",
      "scenarios" => %{@scenario => stats(stats_overrides)}
    }

    if mode, do: Map.put(document, "mode", mode), else: document
  end

  defp stats(overrides) do
    Keyword.merge([median_ns: 100, p99_ns: 150, memory_bytes: 10], overrides)
    |> Map.new(fn {key, value} -> {Atom.to_string(key), value} end)
  end
end
