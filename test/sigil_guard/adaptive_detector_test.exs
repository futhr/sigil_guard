defmodule SigilGuard.AdaptiveDetectorTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.AdaptiveDetector
  alias SigilGuard.Boundary

  # Returns whatever `:return` opt is given, so one detector exercises every
  # result shape; crash/slow detectors are separate.
  defmodule EchoDetector do
    @spec analyze(term(), term(), keyword()) :: term()
    def analyze(_, _, opts), do: Keyword.fetch!(opts, :return)
  end

  defmodule CrashDetector do
    @spec analyze(term(), term(), keyword()) :: term()
    def analyze(_, _, _), do: raise("boom")
  end

  defmodule SlowDetector do
    @spec analyze(term(), term(), keyword()) :: term()
    def analyze(_, _, _) do
      receive do
        :release -> {:ok, []}
      end
    end
  end

  defp run(opts) do
    AdaptiveDetector.run(Boundary.new(%{phase: :model_egress}), opts)
  end

  defp echo(return, extra \\ []) do
    run([{:adaptive_detector, EchoDetector}, {:return, return} | extra])
  end

  describe "nil path" do
    test "an unset detector yields an empty, no-op result" do
      assert run([]) == %{indicators: [], risk_level: nil, error: nil}
      assert run(adaptive_detector: nil) == %{indicators: [], risk_level: nil, error: nil}
    end
  end

  describe "well-formed indicators" do
    test "validated indicators are tagged with source :adaptive" do
      result = echo({:ok, [%{id: "inj-1", severity: :high, confidence: 0.9, note: "n"}]})

      assert result.error == nil
      assert result.risk_level == :high

      assert result.indicators == [
               %{id: "inj-1", severity: :high, confidence: 0.9, note: "n", source: :adaptive}
             ]
    end

    test "severity drives the risk ladder and the strongest wins" do
      assert echo({:ok, [%{id: "a", severity: :low, confidence: 0.1}]}).risk_level == :low
      assert echo({:ok, [%{id: "a", severity: :medium, confidence: 0.1}]}).risk_level == :medium

      mixed =
        echo(
          {:ok,
           [
             %{id: "a", severity: :low, confidence: 0.1},
             %{id: "b", severity: :high, confidence: 0.2}
           ]}
        )

      assert mixed.risk_level == :high
    end

    test "an empty indicator list is a clean, risk-neutral result" do
      assert echo({:ok, []}) == %{indicators: [], risk_level: nil, error: nil}
    end

    test "confidence bounds 0.0 and 1.0 are inclusive" do
      assert echo({:ok, [%{id: "a", severity: :low, confidence: 0.0}]}).error == nil
      assert echo({:ok, [%{id: "a", severity: :low, confidence: 1.0}]}).error == nil
    end
  end

  describe "all-or-nothing degradation" do
    @degraded %{indicators: [], risk_level: nil, error: :adaptive_error}

    test "a single malformed element degrades the whole result" do
      malformed = [
        %{id: "a", severity: :nuclear, confidence: 0.5},
        %{id: "a", severity: :low, confidence: 1.5},
        %{id: "a", severity: :low, confidence: 1},
        %{severity: :low, confidence: 0.5},
        %{id: "", severity: :low, confidence: 0.5},
        %{id: 123, severity: :low, confidence: 0.5},
        %{id: "a", severity: :low, confidence: 0.5, note: 42},
        "not-a-map"
      ]

      for element <- malformed do
        assert echo({:ok, [element]}) == @degraded, inspect(element)
      end
    end

    test "one bad element poisons an otherwise-good batch" do
      good = %{id: "a", severity: :high, confidence: 0.9}
      bad = %{id: "b", severity: :bogus, confidence: 0.9}
      assert echo({:ok, [good, bad]}) == @degraded
    end

    test "a detector error degrades" do
      assert echo({:error, :model_unavailable}) == @degraded
    end

    test "a non-list top level degrades" do
      assert echo({:ok, :nope}) == @degraded
      assert echo(:garbage) == @degraded
    end

    test "a crash degrades" do
      assert run(adaptive_detector: CrashDetector) == @degraded
    end

    test "a timeout degrades" do
      assert run(adaptive_detector: SlowDetector, hook_timeout_ms: 20) == @degraded
    end
  end

  describe "telemetry" do
    setup do
      handler = "adaptive-test-#{inspect(make_ref())}"
      parent = self()

      :telemetry.attach(
        handler,
        [:sigil_guard, :boundary, :adaptive],
        fn _, _, metadata, _ -> send(parent, {:adaptive, metadata}) end,
        nil
      )

      on_exit(fn -> :telemetry.detach(handler) end)
      :ok
    end

    test "a successful run reports the indicator count and no error" do
      echo({:ok, [%{id: "a", severity: :low, confidence: 0.5}]})
      assert_received {:adaptive, %{indicator_count: 1, error: nil}}
    end

    test "a degraded run reports :adaptive_error" do
      echo({:error, :down})
      assert_received {:adaptive, %{indicator_count: 0, error: :adaptive_error}}
    end
  end
end
