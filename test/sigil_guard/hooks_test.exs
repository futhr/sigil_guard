defmodule SigilGuard.HooksTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Boundary
  alias SigilGuard.Hooks

  defmodule BlockHook do
    @spec on_tool_request(term(), term()) :: term()
    def on_tool_request(_, _), do: {:block, "denied"}
  end

  defmodule ConfirmHook do
    @spec on_tool_request(term(), term()) :: term()
    def on_tool_request(_, _), do: {:confirm, "review needed"}
  end

  defmodule ContinueHook do
    @spec on_tool_request(term(), term()) :: term()
    def on_tool_request(_, _), do: {:ok, :continue}
  end

  defmodule LowRiskHook do
    @spec on_tool_request(term(), term()) :: term()
    def on_tool_request(_, _), do: {:ok, :continue, %{risk_level: :low}}
  end

  defmodule HighRiskHook do
    @spec on_tool_request(term(), term()) :: term()
    def on_tool_request(_, _) do
      {:ok, :continue, %{risk_level: :high, indicators: [%{"category" => "suspicious"}]}}
    end
  end

  defmodule QuarantineHook do
    @spec on_tool_request(term(), term()) :: term()
    def on_tool_request(_, _), do: {:quarantine, "nope"}
  end

  defmodule InvalidHook do
    @spec on_tool_request(term(), term()) :: term()
    def on_tool_request(_, _), do: :banana
  end

  defmodule BadSignalHook do
    @spec on_tool_request(term(), term()) :: term()
    def on_tool_request(_, _), do: {:ok, :continue, %{risk_level: :nuclear}}
  end

  defmodule CrashHook do
    @spec on_tool_request(term(), term()) :: term()
    def on_tool_request(_, _), do: raise("boom")
  end

  defmodule SlowHook do
    @spec on_tool_request(term(), term()) :: term()
    def on_tool_request(_, _) do
      receive do
        :release -> {:ok, :continue}
      end
    end
  end

  defmodule ThrowHook do
    @spec on_tool_request(term(), term()) :: term()
    def on_tool_request(_, _), do: throw(:boom)
  end

  defmodule ExitHook do
    @spec on_tool_request(term(), term()) :: term()
    def on_tool_request(_, _), do: exit(:boom)
  end

  defmodule IndicatorOnlyHook do
    @spec on_tool_request(term(), term()) :: term()
    def on_tool_request(_, _), do: {:ok, :continue, %{indicators: [%{"category" => "note"}]}}
  end

  defmodule NotifyBehaviourHook do
    @behaviour SigilGuard.Hooks
    @impl SigilGuard.Hooks
    @spec on_session_start(term(), term()) :: term()
    def on_session_start(_, _), do: {:ok, %{risk_level: :medium}}
  end

  defmodule NotifyBlockHook do
    @spec on_session_start(term(), term()) :: term()
    def on_session_start(_, _), do: {:block, "cannot"}
  end

  defmodule NotifyCrashHook do
    @spec on_session_start(term(), term()) :: term()
    def on_session_start(_, _), do: raise("boom")
  end

  defmodule NotifySlowHook do
    @spec on_session_start(term(), term()) :: term()
    def on_session_start(_, _) do
      receive do
        :release -> :ok
      end
    end
  end

  defp dispatch(hooks, phase, opts \\ []) do
    Hooks.dispatch(Boundary.new(%{phase: phase}), Keyword.put(opts, :hooks, hooks))
  end

  defp ids(result), do: Enum.map(result.contributions, fn {_, [rule]} -> rule["id"] end)
  defp verdicts(result), do: Enum.map(result.contributions, &elem(&1, 0))

  describe "dispatch/2 result semantics" do
    test "no hooks or a non-matching phase yields an empty result" do
      assert dispatch([], :tool_request) == %{contributions: [], risk_level: nil, indicators: []}

      # ContinueHook only exports on_tool_request; at tool_result it is skipped.
      assert dispatch([ContinueHook], :tool_result) ==
               %{contributions: [], risk_level: nil, indicators: []}
    end

    test "a block contributes :block with rule id hook.<module>.<phase>" do
      result = dispatch([BlockHook], :tool_request)
      assert verdicts(result) == [:block]
      assert ids(result) == ["hook.#{inspect(BlockHook)}.tool_request"]

      [{:block, [rule]}] = result.contributions
      assert rule["explanation"] == "denied"
    end

    test "a confirm contributes :confirm" do
      result = dispatch([ConfirmHook], :tool_request)
      assert verdicts(result) == [:confirm]
      assert ids(result) == ["hook.#{inspect(ConfirmHook)}.tool_request"]
    end

    test "a plain continue contributes nothing" do
      assert dispatch([ContinueHook], :tool_request) ==
               %{contributions: [], risk_level: nil, indicators: []}
    end

    test "a signal raises risk and tags indicators with source :hook" do
      result = dispatch([HighRiskHook], :tool_request)
      assert result.contributions == []
      assert result.risk_level == :high
      assert result.indicators == [%{"category" => "suspicious", "source" => :hook}]
    end

    test "accumulated risk takes the maximum and never lowers" do
      assert dispatch([HighRiskHook, LowRiskHook], :tool_request).risk_level == :high
      assert dispatch([LowRiskHook, HighRiskHook], :tool_request).risk_level == :high

      # A later signal with no risk_level leaves the accumulated risk intact.
      result = dispatch([HighRiskHook, IndicatorOnlyHook], :tool_request)
      assert result.risk_level == :high

      assert result.indicators == [
               %{"category" => "suspicious", "source" => :hook},
               %{"category" => "note", "source" => :hook}
             ]
    end

    test "a block short-circuits the remaining hooks" do
      result = dispatch([BlockHook, ConfirmHook], :tool_request)
      assert verdicts(result) == [:block]
    end

    test "non-blocking results accumulate in registration order" do
      result = dispatch([ConfirmHook, HighRiskHook], :tool_request)
      assert verdicts(result) == [:confirm]
      assert result.risk_level == :high
      assert result.indicators == [%{"category" => "suspicious", "source" => :hook}]
    end

    test "a quarantine result is not allowed and fails closed to block" do
      result = dispatch([QuarantineHook], :tool_request)
      assert verdicts(result) == [:block]
      assert [{:block, [rule]}] = result.contributions
      assert rule["explanation"] == "invalid_hook_result"
    end

    test "a malformed signal fails closed to block on a blockable phase" do
      assert verdicts(dispatch([BadSignalHook], :tool_request)) == [:block]
    end
  end

  describe "fail-closed matrix (blockable phase)" do
    test "an invalid result blocks with reason :invalid_hook_result" do
      assert [{:block, [rule]}] = dispatch([InvalidHook], :tool_request).contributions
      assert rule["explanation"] == "invalid_hook_result"
    end

    test "a crash blocks with reason :hook_crash" do
      assert [{:block, [rule]}] = dispatch([CrashHook], :tool_request).contributions
      assert rule["explanation"] == "hook_crash"
    end

    test "a thrown or exited hook also fails closed to :hook_crash" do
      for hook <- [ThrowHook, ExitHook] do
        assert [{:block, [rule]}] = dispatch([hook], :tool_request).contributions
        assert rule["explanation"] == "hook_crash", inspect(hook)
      end
    end

    test "a timeout blocks with reason :hook_timeout" do
      result = dispatch([SlowHook], :tool_request, hook_timeout_ms: 20)
      assert [{:block, [rule]}] = result.contributions
      assert rule["explanation"] == "hook_timeout"
    end

    test "malformed hook options block without raising" do
      boundary = Boundary.new(%{phase: :tool_request})

      for opts <- [
            :not_options,
            [hooks: :not_a_list],
            [hooks: ["not-a-module"]],
            [hooks: [ContinueHook], hook_timeout_ms: -1],
            [hooks: [ContinueHook], hook_timeout_ms: :infinity],
            [hooks: [ContinueHook], hook_timeout_ms: 4_294_967_296]
          ] do
        assert [{:block, [rule]}] = Hooks.dispatch(boundary, opts).contributions
        assert rule["explanation"] == "invalid_hook_options"
      end
    end
  end

  describe "fail-closed matrix (notification-only phase)" do
    test "a valid notify signal is accepted" do
      result = dispatch([NotifyBehaviourHook], :session_start)
      assert result.contributions == []
      assert result.risk_level == :medium
    end

    test "an invalid deny verdict logs and continues, contributing nothing" do
      assert dispatch([NotifyBlockHook], :session_start).contributions == []
    end

    test "a crash logs and continues, contributing nothing" do
      assert dispatch([NotifyCrashHook], :session_start).contributions == []
    end

    test "a timeout logs and continues, contributing nothing" do
      assert dispatch([NotifySlowHook], :session_start, hook_timeout_ms: 20).contributions == []
    end

    test "malformed options log and continue" do
      boundary = Boundary.new(%{phase: :session_start})
      assert Hooks.dispatch(boundary, hooks: :not_a_list).contributions == []
    end

    test "notify failures emit the boundary hook telemetry event" do
      ref = make_ref()
      parent = self()
      handler = "hooks-test-#{inspect(ref)}"

      :telemetry.attach(
        handler,
        [:sigil_guard, :boundary, :hook],
        fn _, measurements, metadata, _ ->
          send(parent, {:hook_event, measurements, metadata})
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach(handler) end)

      dispatch([NotifyCrashHook], :session_start)

      assert_received {:hook_event, %{duration: duration},
                       %{hook_result: :hook_crash, phase: :session_start}}

      assert is_integer(duration) and duration >= 0
    end

    test "successful hooks emit their normalized outcome and duration" do
      ref = make_ref()
      parent = self()
      handler = "hooks-success-test-#{inspect(ref)}"

      :telemetry.attach(
        handler,
        [:sigil_guard, :boundary, :hook],
        fn _, measurements, metadata, _ ->
          send(parent, {:hook_success_event, measurements, metadata})
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach(handler) end)

      dispatch([ContinueHook], :tool_request)

      assert_received {:hook_success_event, %{duration: duration},
                       %{
                         module: module,
                         phase: :tool_request,
                         hook_result: :continue
                       }}

      assert module == inspect(ContinueHook)
      assert is_integer(duration) and duration >= 0
    end
  end
end
