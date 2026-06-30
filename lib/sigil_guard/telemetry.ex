defmodule SigilGuard.Telemetry do
  @moduledoc """
  Telemetry event definitions and span helpers for SigilGuard.

  All SigilGuard operations emit `:telemetry` events that you can attach
  handlers to for metrics, logging, or alerting. The helpers in this module
  can also translate SigilGuard metadata into OpenTelemetry-style string
  attributes for span/event exporters.

  ## Subscribing to Events

      :telemetry.attach_many(
        "sigil-guard-logger",
        SigilGuard.Telemetry.events(),
        &MyApp.TelemetryHandler.handle_event/4,
        nil
      )

  ## OpenTelemetry Bridge

      SigilGuard.Telemetry.attach_otel_forwarder(
        "sigil-guard-otel",
        fn event, measurements, metadata, attributes ->
          MyApp.OTelForwarder.record(event, measurements, metadata, attributes)
        end
      )

  ## Events

    * `[:sigil_guard, :scan, :start | :stop | :exception]`
      Measurements: `%{system_time: integer}` (start), `%{duration: integer}` (stop)
      Metadata: `%{hit_count: integer, patterns_checked: integer, pipeline: atom,
      scanner_validate: boolean}`

    * `[:sigil_guard, :envelope, :sign | :verify]`
      Measurements: `%{duration: integer}`
      Metadata: `%{identity: String.t(), verdict: atom, outcome: :ok | :error}`

    * `[:sigil_guard, :registry, :fetch, :start | :stop | :exception]`
      Measurements: `%{duration: integer}`
      Metadata: `%{url: String.t(), count: integer, source: atom}`

    * `[:sigil_guard, :policy, :decision]`
      Measurements: `%{system_time: integer}`
      Metadata: `%{action: String.t(), risk_level: atom, verdict: atom, trust_required: atom}`

    * `[:sigil_guard, :runtime, :gate]`
      Measurements: `%{system_time: integer}`
      Metadata: `%{phase: atom, origin: atom, sink: atom, tool: String.t() | nil,
      trust_zone: atom, trust_level: atom, risk_level: atom, verdict: atom,
      action: atom, hit_count: integer, indicator_count: integer,
      indicator_ids: [atom], content_hash: String.t(), action_digest: String.t() | nil,
      repo_policy_verdict: atom, repo_policy_rules: [String.t()],
      repo_unmatched_paths: [String.t()]}`

    * `[:sigil_guard, :audit, :logged]`
      Measurements: `%{system_time: integer}`
      Metadata: `%{event_type: String.t(), actor: String.t(), action: String.t(),
      result: String.t()}`

  """

  @events [
    [:sigil_guard, :scan, :start],
    [:sigil_guard, :scan, :stop],
    [:sigil_guard, :scan, :exception],
    [:sigil_guard, :envelope, :sign],
    [:sigil_guard, :envelope, :verify],
    [:sigil_guard, :registry, :fetch, :start],
    [:sigil_guard, :registry, :fetch, :stop],
    [:sigil_guard, :registry, :fetch, :exception],
    [:sigil_guard, :policy, :decision],
    [:sigil_guard, :runtime, :gate],
    [:sigil_guard, :audit, :logged]
  ]

  @attribute_map %{
    action: "sigil.security.action",
    action_digest: "sigil.security.action_digest",
    actor: "sigil.actor",
    content_hash: "sigil.security.content_hash",
    count: "sigil.registry.count",
    endpoint: "sigil.registry.endpoint",
    event_type: "sigil.audit.event_type",
    hit_count: "sigil.security.hit_count",
    indicator_count: "sigil.security.indicator_count",
    indicator_ids: "sigil.security.indicator_ids",
    mcp_server: "sigil.mcp.server",
    origin: "sigil.security.origin",
    patterns_checked: "sigil.scanner.patterns_checked",
    phase: "sigil.security.phase",
    pipeline: "sigil.scanner.pipeline",
    result: "sigil.audit.result",
    resource_uri: "sigil.resource.uri",
    repo_policy_error: "sigil.repo_policy.error",
    repo_policy_rules: "sigil.repo_policy.rules",
    repo_policy_verdict: "sigil.repo_policy.verdict",
    repo_unmatched_paths: "sigil.repo_policy.unmatched_paths",
    risk_level: "sigil.security.risk_level",
    scanner_validate: "sigil.scanner.validate",
    sink: "sigil.security.sink",
    source: "sigil.registry.source",
    tool: "sigil.security.tool.name",
    trust_level: "sigil.security.trust_level",
    trust_required: "sigil.security.trust_required",
    trust_zone: "sigil.security.trust_zone",
    url: "url.full",
    verdict: "sigil.security.verdict"
  }

  @typedoc "OpenTelemetry-compatible scalar or scalar-array attribute value."
  @type otel_value :: String.t() | number() | boolean() | [String.t() | number() | boolean()]

  @typedoc "Non-empty Telemetry event name."
  @type event_name :: [atom(), ...]

  @doc "Execute a telemetry span with the given event prefix."
  @spec span(event_name(), map(), (-> {term(), map()})) :: term()
  def span(event_prefix, metadata, fun) do
    :telemetry.span(event_prefix, metadata, fun)
  end

  @doc "Emit a single telemetry event."
  @spec emit(event_name(), map(), map()) :: :ok
  def emit(event, measurements, metadata) do
    :telemetry.execute(event, measurements, metadata)
  end

  @doc "Return all SigilGuard telemetry events known to this version."
  @spec events() :: [event_name(), ...]
  def events, do: @events

  @doc """
  Attach a forwarding handler that receives OTel-style attributes.

  The `forwarder` function is called as:

      forwarder.(event, measurements, metadata, attributes)

  This keeps OpenTelemetry optional. Applications that depend on an OTel
  package can set span/log attributes inside the forwarder.
  """
  @spec attach_otel_forwarder(
          String.t(),
          (event_name(), map(), map(), %{String.t() => otel_value()} -> term()),
          keyword()
        ) :: :ok | {:error, :already_exists}
  def attach_otel_forwarder(handler_id, forwarder, opts \\ [])
      when is_binary(handler_id) and is_function(forwarder, 4) do
    events = Keyword.get(opts, :events, @events)

    :telemetry.attach_many(
      handler_id,
      events,
      fn event, measurements, metadata, _ ->
        attributes = otel_attributes(event, measurements, metadata)
        forwarder.(event, measurements, metadata, attributes)
      end,
      nil
    )
  end

  @doc "Detach a telemetry handler created with `attach_otel_forwarder/3`."
  @spec detach(String.t()) :: :ok | {:error, :not_found}
  def detach(handler_id) do
    :telemetry.detach(handler_id)
  end

  @doc """
  Convert SigilGuard telemetry metadata to OpenTelemetry-style attributes.

  Official semantic-convention names are used only where they clearly fit
  (`url.full`). SigilGuard-specific security fields use the `sigil.*`
  namespace to avoid depending on unstable security-event conventions.
  """
  @spec otel_attributes(event_name(), map(), map()) :: %{String.t() => otel_value()}
  def otel_attributes(event, measurements \\ %{}, metadata \\ %{}) do
    %{
      "sigil.event" => event_name(event),
      "sigil.component" => component(event),
      "sigil.operation" => operation(event)
    }
    |> merge_measurements(measurements)
    |> merge_metadata(metadata)
  end

  defp merge_measurements(attributes, measurements) do
    measurements
    |> Enum.reduce(attributes, fn {key, value}, acc ->
      put_attribute(acc, "sigil.measurement.#{key}", value)
    end)
  end

  defp merge_metadata(attributes, metadata) do
    Enum.reduce(metadata, attributes, fn {key, value}, acc ->
      case Map.fetch(@attribute_map, key) do
        {:ok, attribute} -> put_attribute(acc, attribute, value)
        :error -> acc
      end
    end)
  end

  defp put_attribute(attributes, _, nil), do: attributes

  defp put_attribute(attributes, key, value) when is_atom(value) do
    Map.put(attributes, key, Atom.to_string(value))
  end

  defp put_attribute(attributes, key, value)
       when is_binary(value) or is_number(value) or is_boolean(value) do
    Map.put(attributes, key, value)
  end

  defp put_attribute(attributes, key, value) when is_list(value) do
    values =
      value
      |> Enum.map(&attribute_value/1)
      |> Enum.reject(&is_nil/1)

    if values == [], do: attributes, else: Map.put(attributes, key, values)
  end

  defp put_attribute(attributes, _, _), do: attributes

  defp attribute_value(value) when is_atom(value), do: Atom.to_string(value)

  defp attribute_value(value) when is_binary(value) or is_number(value) or is_boolean(value),
    do: value

  defp attribute_value(_), do: nil

  defp event_name(event), do: event |> Enum.map_join(".", &Atom.to_string/1)
  defp component([:sigil_guard, component | _]), do: Atom.to_string(component)
  defp component(_), do: "unknown"

  defp operation([:sigil_guard, _ | rest]),
    do: Enum.map_join(rest, ".", &Atom.to_string/1)

  defp operation(_), do: "unknown"
end
