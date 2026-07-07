defmodule SigilGuard.AdaptiveDetector do
  @moduledoc """
  Advisory adaptive-detection behaviour for the boundary kernel (SP.04, D5).

  The behaviour lives in core; model-backed implementations (e.g. an ONNX
  classifier) live in optional post-GA packages. Results are strictly advisory:
  returned indicators join the indicator list with source `:adaptive` and feed
  the risk ladder (`:high` severity raises risk to `:high`, `:medium` to at
  least `:medium`), but they never lower risk and never produce an allow.

  `run/2` is the core-side entry point. With `:adaptive_detector` unset or `nil`
  the behaviour is absent and the result is empty, so a decision is byte-identical
  to a build without a detector. Every returned indicator is validated
  per-element; a detector error, timeout (bounded by `:hook_timeout_ms`), crash,
  a result whose top level is not a list, or any single malformed indicator
  degrades the whole result to zero indicators recorded as `:adaptive_error`
  (all-or-nothing, so a detector cannot smuggle a partial result past validation).
  """

  alias SigilGuard.Boundary
  alias SigilGuard.Telemetry

  @default_timeout_ms 5_000
  @severities [:low, :medium, :high]
  @risk_rank %{low: 0, medium: 1, high: 2}

  @typedoc "A validated advisory indicator returned by a detector."
  @type indicator :: %{
          required(:id) => String.t(),
          required(:severity) => :low | :medium | :high,
          required(:confidence) => float(),
          optional(:note) => String.t()
        }

  @typedoc """
  Aggregate advisory outcome fed back into decision combination.

  `indicators` are the validated indicators tagged source `:adaptive`;
  `risk_level` is the strongest severity raised (or nil); `error` is
  `:adaptive_error` when the whole result was degraded, else nil.
  """
  @type result :: %{
          indicators: [map()],
          risk_level: :low | :medium | :high | nil,
          error: nil | :adaptive_error
        }

  @callback analyze(text :: String.t(), Boundary.t(), opts :: keyword()) ::
              {:ok, [indicator()]} | {:error, atom()}

  @doc """
  Run the configured `:adaptive_detector` and return its advisory result.

  Options: `:adaptive_detector` (a module implementing this behaviour, or nil),
  `:text` (the content to analyze, default `""`), `:hook_timeout_ms` (default
  `5_000`).
  """
  @spec run(Boundary.t(), keyword()) :: result()
  def run(%Boundary{} = boundary, opts) do
    case Keyword.get(opts, :adaptive_detector) do
      nil -> empty()
      detector -> invoke(detector, boundary, opts)
    end
  end

  defp invoke(detector, boundary, opts) do
    text = Keyword.get(opts, :text, "")
    timeout = Keyword.get(opts, :hook_timeout_ms, @default_timeout_ms)

    fn -> detector.analyze(text, boundary, opts) end
    |> run_bounded(timeout)
    |> interpret(detector)
  end

  defp interpret({:ok, {:ok, indicators}}, detector) when is_list(indicators) do
    case validate_all(indicators) do
      {:ok, validated} -> success(validated, detector)
      :error -> degraded(detector)
    end
  end

  defp interpret(_, detector), do: degraded(detector)

  defp success(validated, detector) do
    risk = strongest_risk(Enum.map(validated, & &1.severity))
    emit(detector, length(validated), nil)
    tagged = Enum.map(validated, &Map.put(&1, :source, :adaptive))
    %{indicators: tagged, risk_level: risk, error: nil}
  end

  defp degraded(detector) do
    emit(detector, 0, :adaptive_error)
    %{indicators: [], risk_level: nil, error: :adaptive_error}
  end

  defp empty, do: %{indicators: [], risk_level: nil, error: nil}

  # -- Per-element validation (all-or-nothing) --------------------------------

  defp validate_all(indicators) do
    if Enum.all?(indicators, &well_formed?/1), do: {:ok, indicators}, else: :error
  end

  defp well_formed?(%{id: id, severity: severity, confidence: confidence} = indicator) do
    is_binary(id) and id != "" and severity in @severities and
      valid_confidence?(confidence) and valid_note?(Map.get(indicator, :note))
  end

  defp well_formed?(_), do: false

  defp valid_confidence?(confidence) do
    is_float(confidence) and confidence >= 0.0 and confidence <= 1.0
  end

  defp valid_note?(nil), do: true
  defp valid_note?(note), do: is_binary(note)

  # -- Risk ladder ------------------------------------------------------------

  defp strongest_risk([]), do: nil

  defp strongest_risk(severities) do
    Enum.max_by(severities, &Map.fetch!(@risk_rank, &1))
  end

  # -- Bounded invocation -----------------------------------------------------

  defp run_bounded(fun, timeout) do
    parent = self()
    ref = make_ref()
    {pid, monitor} = spawn_monitor(fn -> send(parent, {ref, safe_call(fun)}) end)

    receive do
      {^ref, {:ok, value}} ->
        Process.demonitor(monitor, [:flush])
        {:ok, value}

      {^ref, :crash} ->
        Process.demonitor(monitor, [:flush])
        :crash

      {:DOWN, ^monitor, :process, ^pid, _} ->
        :crash
    after
      timeout ->
        Process.exit(pid, :kill)
        Process.demonitor(monitor, [:flush])
        :timeout
    end
  end

  # Catch in-process so a crashing detector degrades to zero indicators without
  # emitting a SASL error report; uncatchable exits still surface via `:DOWN`.
  defp safe_call(fun) do
    {:ok, fun.()}
  rescue
    _ -> :crash
  catch
    _, _ -> :crash
  end

  defp emit(detector, indicator_count, error) do
    Telemetry.emit([:sigil_guard, :boundary, :adaptive], %{}, %{
      detector: inspect(detector),
      indicator_count: indicator_count,
      error: error
    })
  end
end
