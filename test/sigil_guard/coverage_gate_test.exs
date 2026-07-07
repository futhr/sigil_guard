defmodule SigilGuard.CoverageGateTest do
  @moduledoc false

  use ExUnit.Case, async: true

  @coveralls_config Path.expand("../../coveralls.json", __DIR__)

  test "coverage tool configuration enforces the minimum coverage floor" do
    assert {:ok, %{"coverage_options" => %{"minimum_coverage" => 95}}} =
             @coveralls_config
             |> File.read!()
             |> Jason.decode()

    script = ~S"""
    stats = [%{name: "synthetic.ex", source: "covered\nmissed", coverage: [1, 0]}]
    ExCoveralls.Stats.ensure_minimum_coverage(stats)
    """

    {output, status} =
      System.cmd("mix", ["run", "--no-start", "-e", script],
        env: [{"MIX_ENV", "test"}],
        stderr_to_stdout: true
      )

    assert status == 1
    assert output =~ "FAILED: Expected minimum coverage of 95%, got 50.0%."
  end
end
