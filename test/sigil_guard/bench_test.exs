defmodule SigilGuard.BenchTest do
  @moduledoc false

  use ExUnit.Case, async: false

  Code.require_file("../../bench/corpus.exs", __DIR__)
  Code.require_file("../../bench/run.exs", __DIR__)

  @secret "AKIAIOSFODNN7EXAMPLE"

  test "corpus generation is byte-identical from the fixed seed" do
    first = tmp_dir("first")
    second = tmp_dir("second")

    SigilGuard.BenchCorpus.generate!(first)
    SigilGuard.BenchCorpus.generate!(second)

    first_files = relative_files(first)
    assert first_files == relative_files(second)

    for file <- first_files do
      assert File.read!(Path.join(first, file)) == File.read!(Path.join(second, file))
    end
  end

  test "committed hit corpora satisfy the SP.15 precondition" do
    SigilGuard.Bench.assert_corpus!()

    for {name, expected_hits} <- [
          {"clean_1k.txt", 0},
          {"clean_64k.txt", 0},
          {"clean_1m.txt", 0},
          {"hits_1k.txt", 0},
          {"hits_64k.txt", 16},
          {"hits_1m.txt", 256}
        ] do
      payload = File.read!(Path.join("bench/corpus", name))
      assert length(Regex.scan(~r/#{@secret}/, payload)) == expected_hits
    end
  end

  test "benchmark harness covers the BM.01 through BM.08 scenario matrix" do
    assert SigilGuard.Bench.scenario_ids() ==
             MapSet.new(~w[BM.01 BM.02 BM.03 BM.04 BM.05 BM.06 BM.07 BM.08])

    scenarios = SigilGuard.Bench.scenarios()

    assert map_size(scenarios) == 20
    assert Enum.any?(scenarios, &match?({"BM.08 no-op baseline", _}, &1))
    assert Enum.any?(scenarios, &match?({"BM.08 tool gateway guard_request", _}, &1))
  end

  test "smoke mode keeps full Benchee settings only for real runs" do
    assert SigilGuard.Bench.bench_config(false) == [warmup: 2, time: 5, memory_time: 2]
    assert SigilGuard.Bench.bench_config(true) == [warmup: 0, time: 0.01, memory_time: 0]
  end

  defp relative_files(dir) do
    dir
    |> Path.join("**/*")
    |> Path.wildcard()
    |> Enum.reject(&File.dir?/1)
    |> Enum.map(&Path.relative_to(&1, dir))
    |> Enum.sort()
  end

  defp tmp_dir(name) do
    path = Path.join(System.tmp_dir!(), "sigil_guard_bench_#{name}_#{System.unique_integer()}")
    File.rm_rf!(path)
    path
  end
end
