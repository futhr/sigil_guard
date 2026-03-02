defmodule SigilGuard.Telemetry do
  @moduledoc """
  Telemetry event definitions and span helpers for SigilGuard.

  All SigilGuard operations emit `:telemetry` events that you can attach
  handlers to for metrics, logging, or alerting.

  ## Subscribing to Events

      :telemetry.attach_many(
        "sigil-guard-logger",
        [
          [:sigil_guard, :scan, :stop],
          [:sigil_guard, :envelope, :sign],
          [:sigil_guard, :policy, :decision]
        ],
        &MyApp.TelemetryHandler.handle_event/4,
        nil
      )

  ## Events

    * `[:sigil_guard, :scan, :start | :stop | :exception]`
      Measurements: `%{system_time: integer}` (start), `%{duration: integer}` (stop)
      Metadata: `%{hit_count: integer, patterns_checked: integer}`

    * `[:sigil_guard, :envelope, :sign | :verify]`
      Measurements: `%{duration: integer}`
      Metadata: `%{identity: String.t(), verdict: atom, outcome: :ok | :error}`

    * `[:sigil_guard, :registry, :fetch, :start | :stop | :exception]`
      Measurements: `%{duration: integer}`
      Metadata: `%{url: String.t(), count: integer, source: atom}`

    * `[:sigil_guard, :policy, :decision]`
      Measurements: `%{system_time: integer}`
      Metadata: `%{action: String.t(), risk_level: atom, verdict: atom, trust_required: atom}`

    * `[:sigil_guard, :audit, :logged]`
      Measurements: `%{system_time: integer}`
      Metadata: `%{event_type: String.t(), actor: String.t()}`

  """

  @doc "Execute a telemetry span with the given event prefix."
  @spec span(list(atom()), map(), (-> {term(), map()})) :: term()
  def span(event_prefix, metadata, fun) do
    :telemetry.span(event_prefix, metadata, fun)
  end

  @doc "Emit a single telemetry event."
  @spec emit(list(atom()), map(), map()) :: :ok
  def emit(event, measurements, metadata) do
    :telemetry.execute(event, measurements, metadata)
  end
end
