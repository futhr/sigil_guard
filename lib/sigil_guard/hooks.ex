defmodule SigilGuard.Hooks do
  @moduledoc """
  Host lifecycle hooks for the boundary kernel (SP.04).

  Hooks let a host extend `SigilGuard.BoundaryPolicy` with deny-side verdicts
  and advisory signals; they can never weaken a deterministic decision. Each
  callback maps 1:1 to a lifecycle phase as `on_<phase>` and is optional. The
  lifecycle `Blockable` column is normative: `on_session_start/2` and
  `on_session_end/2` are notification-only, the other seven are blockable.

  `dispatch/3` invokes the callback matching the boundary phase on each hook in
  registration order, time-bounded by `:hook_timeout_ms` (default `5_000`).
  Results:

  - `{:ok, :continue}` / `:ok` - proceed.
  - `{:ok, :continue, signal}` / `{:ok, signal}` - proceed with an advisory
    `t:hook_signal/0` (a `risk_level` that may only raise computed risk, and
    `indicators` joined with source `:hook`).
  - `{:block, reason}` - a `:block` contribution; short-circuits remaining hooks.
  - `{:confirm, reason}` - a `:confirm` contribution.

  Hooks cannot emit `allow`, `redact`, or `quarantine`. Any other return is
  `:invalid_hook_result`. On a blockable phase, a timeout (`:hook_timeout`),
  crash (`:hook_crash`), or `:invalid_hook_result` fails closed to a `:block`
  contribution; on a notification-only phase the same failures log-and-continue
  via telemetry. Verdict contributions carry matched rule id
  `hook.<module>.<phase>`.
  """

  alias SigilGuard.Boundary
  alias SigilGuard.Lifecycle
  alias SigilGuard.Telemetry

  @default_timeout_ms 5_000
  @risk_rank %{low: 0, medium: 1, high: 2}

  @callback_for %{
    session_start: :on_session_start,
    tool_request: :on_tool_request,
    permission_requested: :on_permission_requested,
    permission_resolved: :on_permission_resolved,
    tool_result: :on_tool_result,
    file_changed: :on_file_changed,
    model_ingress: :on_model_ingress,
    model_egress: :on_model_egress,
    session_end: :on_session_end
  }

  @typedoc "Advisory signal a hook may attach to a non-blocking result."
  @type hook_signal :: %{
          optional(:risk_level) => :low | :medium | :high,
          optional(:indicators) => [map()],
          optional(:note) => String.t()
        }

  @typedoc "Result contract for a blockable-phase callback."
  @type blockable_result ::
          {:ok, :continue}
          | {:ok, :continue, hook_signal()}
          | {:block, String.t()}
          | {:confirm, String.t()}

  @typedoc "Result contract for a notification-only callback."
  @type notify_result :: :ok | {:ok, hook_signal()}

  @typedoc """
  Aggregate hook outcome fed back into decision combination.

  `contributions` is the ordered list of `{:block | :confirm, [rule]}` verdicts;
  `risk_level` is the strongest advisory risk raised (or nil); `indicators` are
  the accumulated advisory indicators, each tagged source `:hook`.
  """
  @type result :: %{
          contributions: [{:block | :confirm, [map()]}],
          risk_level: :low | :medium | :high | nil,
          indicators: [map()]
        }

  @callback on_session_start(Boundary.t(), keyword()) :: notify_result()
  @callback on_tool_request(Boundary.t(), keyword()) :: blockable_result()
  @callback on_permission_requested(Boundary.t(), keyword()) :: blockable_result()
  @callback on_permission_resolved(Boundary.t(), keyword()) :: blockable_result()
  @callback on_tool_result(Boundary.t(), keyword()) :: blockable_result()
  @callback on_file_changed(Boundary.t(), keyword()) :: blockable_result()
  @callback on_model_ingress(Boundary.t(), keyword()) :: blockable_result()
  @callback on_model_egress(Boundary.t(), keyword()) :: blockable_result()
  @callback on_session_end(Boundary.t(), keyword()) :: notify_result()

  @optional_callbacks on_session_start: 2,
                      on_tool_request: 2,
                      on_permission_requested: 2,
                      on_permission_resolved: 2,
                      on_tool_result: 2,
                      on_file_changed: 2,
                      on_model_ingress: 2,
                      on_model_egress: 2,
                      on_session_end: 2

  @doc """
  Invoke the phase-matching callback on each hook and aggregate the outcome.

  Options: `:hooks` (a list of modules in invocation order), `:hook_timeout_ms`
  (default `5_000`), and any keyword passed through to each callback.
  """
  @spec dispatch(Boundary.t(), keyword()) :: result()
  def dispatch(%Boundary{} = boundary, opts) do
    hooks = Keyword.get(opts, :hooks, [])
    callback = Map.get(@callback_for, boundary.phase)

    if callback == nil or hooks == [] do
      empty_result()
    else
      run_hooks(hooks, boundary, callback, opts)
    end
  end

  defp run_hooks(hooks, boundary, callback, opts) do
    blockable? = Lifecycle.blockable?(boundary.phase)
    timeout = Keyword.get(opts, :hook_timeout_ms, @default_timeout_ms)

    hooks
    |> Enum.reduce_while(empty_result(), fn module, acc ->
      if exports?(module, callback) do
        outcome = invoke(module, callback, boundary, opts, timeout)
        fold(interpret(outcome, module, boundary.phase, blockable?), acc)
      else
        {:cont, acc}
      end
    end)
    |> finalize()
  end

  # Contributions accumulate reversed (prepend) and are restored to registration
  # order once the fold is done.
  defp finalize(acc), do: %{acc | contributions: Enum.reverse(acc.contributions)}

  defp fold(:continue, acc), do: {:cont, acc}

  defp fold({:signal, signal}, acc), do: {:cont, apply_signal(acc, signal)}

  defp fold({:confirm, rule}, acc) do
    {:cont, %{acc | contributions: [{:confirm, [rule]} | acc.contributions]}}
  end

  defp fold({:block, rule}, acc) do
    {:halt, %{acc | contributions: [{:block, [rule]} | acc.contributions]}}
  end

  # -- Result interpretation --------------------------------------------------

  defp interpret({:ok, value}, module, phase, blockable?) do
    interpret_value(value, module, phase, blockable?)
  end

  defp interpret({:error, reason}, module, phase, blockable?) do
    emit(module, phase, reason)
    fail_closed(reason, module, phase, blockable?)
  end

  # Deny-side verdicts are valid only on blockable phases. On a notification-only
  # phase they are a contract violation (handled as invalid-result: log-and-continue).
  defp interpret_value({:block, reason}, module, phase, true) when is_binary(reason) do
    {:block, rule(module, phase, reason)}
  end

  defp interpret_value({:confirm, reason}, module, phase, true) when is_binary(reason) do
    {:confirm, rule(module, phase, reason)}
  end

  defp interpret_value({:ok, :continue}, _, _, _), do: :continue
  defp interpret_value(:ok, _, _, _), do: :continue

  defp interpret_value({:ok, :continue, signal}, module, phase, blockable?) when is_map(signal) do
    signal_or_invalid(signal, module, phase, blockable?)
  end

  defp interpret_value({:ok, signal}, module, phase, blockable?) when is_map(signal) do
    signal_or_invalid(signal, module, phase, blockable?)
  end

  defp interpret_value(_, module, phase, blockable?) do
    emit(module, phase, :invalid_hook_result)
    fail_closed(:invalid_hook_result, module, phase, blockable?)
  end

  defp signal_or_invalid(signal, module, phase, blockable?) do
    case normalize_signal(signal) do
      {:ok, normalized} ->
        {:signal, normalized}

      :error ->
        emit(module, phase, :invalid_hook_result)
        fail_closed(:invalid_hook_result, module, phase, blockable?)
    end
  end

  defp fail_closed(reason, module, phase, true), do: {:block, rule(module, phase, reason)}
  defp fail_closed(_, _, _, false), do: :continue

  # -- Signal normalization ---------------------------------------------------

  defp normalize_signal(signal) do
    with {:ok, risk} <- signal_risk(signal),
         {:ok, indicators} <- signal_indicators(signal) do
      {:ok, %{risk_level: risk, indicators: indicators}}
    end
  end

  defp signal_risk(signal) do
    case Map.get(signal, :risk_level) do
      nil -> {:ok, nil}
      level when is_map_key(@risk_rank, level) -> {:ok, level}
      _ -> :error
    end
  end

  defp signal_indicators(signal) do
    case Map.get(signal, :indicators, []) do
      list when is_list(list) -> tag_indicators(list)
      _ -> :error
    end
  end

  defp tag_indicators(list) do
    if Enum.all?(list, &is_map/1) do
      {:ok, Enum.map(list, &Map.put(&1, "source", :hook))}
    else
      :error
    end
  end

  defp apply_signal(acc, signal) do
    %{
      acc
      | risk_level: max_risk(acc.risk_level, signal.risk_level),
        indicators: acc.indicators ++ signal.indicators
    }
  end

  defp max_risk(nil, other), do: other
  defp max_risk(current, nil), do: current

  defp max_risk(current, other) do
    if Map.fetch!(@risk_rank, other) > Map.fetch!(@risk_rank, current), do: other, else: current
  end

  # -- Bounded invocation -----------------------------------------------------

  defp invoke(module, callback, boundary, opts, timeout) do
    run_bounded(fn -> apply(module, callback, [boundary, opts]) end, timeout)
  end

  defp run_bounded(fun, timeout) do
    parent = self()
    ref = make_ref()
    {pid, monitor} = spawn_monitor(fn -> send(parent, {ref, safe_call(fun)}) end)

    receive do
      {^ref, outcome} ->
        Process.demonitor(monitor, [:flush])
        outcome

      {:DOWN, ^monitor, :process, ^pid, _} ->
        {:error, :hook_crash}
    after
      timeout ->
        Process.exit(pid, :kill)
        Process.demonitor(monitor, [:flush])
        {:error, :hook_timeout}
    end
  end

  # Catch in-process so a crashing hook fails closed to `:hook_crash` without
  # emitting a SASL error report; uncatchable exits still surface via `:DOWN`.
  defp safe_call(fun) do
    {:ok, fun.()}
  rescue
    _ -> {:error, :hook_crash}
  catch
    _, _ -> {:error, :hook_crash}
  end

  # -- Helpers ----------------------------------------------------------------

  defp exports?(module, callback), do: function_exported?(module, callback, 2)

  defp rule(module, phase, reason) do
    %{"id" => "hook.#{inspect(module)}.#{phase}", "explanation" => to_string(reason)}
  end

  defp empty_result, do: %{contributions: [], risk_level: nil, indicators: []}

  defp emit(module, phase, result) do
    Telemetry.emit([:sigil_guard, :boundary, :hook], %{}, %{
      module: inspect(module),
      phase: phase,
      hook_result: result
    })
  end
end
