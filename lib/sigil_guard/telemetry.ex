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
      actor: String.t() | nil, identity: String.t() | nil, trust_zone: atom,
      trust_level: atom, risk_level: atom, verdict: atom, action: atom,
      hit_count: integer, indicator_count: integer, indicator_ids: [atom],
      content_hash: String.t(), action_digest: String.t() | nil,
      action_digest_error: atom | nil, runtime_input_error: atom | nil,
      scanner_error: atom | nil,
      repo_policy_verdict: atom, repo_policy_rules: [String.t()],
      repo_unmatched_paths: [String.t()]}`

    * `[:sigil_guard, :mcp, :request]`
      Measurements: `%{system_time: integer}`
      Metadata: `%{phase: atom, origin: atom, sink: atom, tool: String.t() | nil,
      actor: String.t() | nil, identity: String.t() | nil, trust_zone: atom,
      trust_level: atom, risk_level: atom, verdict: atom, action: atom,
      envelope_status: :valid | :invalid, envelope_reason: atom | nil,
      confirmation_status: :accepted | :invalid | nil,
      confirmation_reason: atom | nil, confirmation_actor: String.t() | nil,
      confirmation_nonce_hash: String.t() | nil,
      content_hash: String.t()}`

    * `[:sigil_guard, :audit, :logged]`
      Measurements: `%{system_time: integer}`
      Metadata: `%{event_type: String.t(), actor: String.t(), action: String.t(),
      result: String.t()}`

    * `[:sigil_guard, :audit, :anchor_store, :put | :fetch | :verify, :start | :stop | :exception]`
      Measurements: `%{system_time: integer}` (start), `%{duration: integer}` (stop)
      Metadata: `%{anchor_store: String.t(), anchor_digest: String.t() | nil,
      anchor_storage: String.t() | nil, anchor_uri_scheme: String.t() | nil,
      outcome: :ok | :error, error_reason: atom | nil}`

    * `[:sigil_guard, :trust_bundle, :load | :verify, :start | :stop | :exception]`
      Measurements: `%{system_time: integer}` (start), `%{duration: integer}` (stop)
      Metadata: `%{source: atom, bundle_id: String.t() | nil, sequence: pos_integer() | nil,
      root_version: pos_integer() | nil, result: :ok | :error | nil, error: atom() | nil,
      dev: boolean()}`

    * `[:sigil_guard, :trust_bundle, :quarantine]`
      Measurements: `%{count: pos_integer()}`
      Metadata: `%{reason: atom(), bundle_id: String.t() | nil,
      bundle_digest: String.t() | nil, dev: boolean()}`

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
    [:sigil_guard, :boundary, :hook],
    [:sigil_guard, :boundary, :adaptive],
    [:sigil_guard, :runtime, :gate],
    [:sigil_guard, :mcp, :request],
    [:sigil_guard, :audit, :logged],
    [:sigil_guard, :audit, :anchor_store, :put, :start],
    [:sigil_guard, :audit, :anchor_store, :put, :stop],
    [:sigil_guard, :audit, :anchor_store, :put, :exception],
    [:sigil_guard, :audit, :anchor_store, :fetch, :start],
    [:sigil_guard, :audit, :anchor_store, :fetch, :stop],
    [:sigil_guard, :audit, :anchor_store, :fetch, :exception],
    [:sigil_guard, :audit, :anchor_store, :verify, :start],
    [:sigil_guard, :audit, :anchor_store, :verify, :stop],
    [:sigil_guard, :audit, :anchor_store, :verify, :exception],
    [:sigil_guard, :trust_bundle, :load, :start],
    [:sigil_guard, :trust_bundle, :load, :stop],
    [:sigil_guard, :trust_bundle, :load, :exception],
    [:sigil_guard, :trust_bundle, :verify, :start],
    [:sigil_guard, :trust_bundle, :verify, :stop],
    [:sigil_guard, :trust_bundle, :verify, :exception],
    [:sigil_guard, :trust_bundle, :quarantine],
    [:sigil_guard, :agent_trust, :card_verify, :start],
    [:sigil_guard, :agent_trust, :card_verify, :stop],
    [:sigil_guard, :agent_trust, :card_verify, :exception],
    [:sigil_guard, :agent_trust, :attest, :start],
    [:sigil_guard, :agent_trust, :attest, :stop],
    [:sigil_guard, :agent_trust, :attest, :exception],
    [:sigil_guard, :agent_trust, :verify, :start],
    [:sigil_guard, :agent_trust, :verify, :stop],
    [:sigil_guard, :agent_trust, :verify, :exception],
    [:sigil_guard, :agent_trust, :quarantine]
  ]

  # V3 attribute namespace (SP.05 D16): `sigilguard.*` throughout. The mapping is
  # mechanical - leading `sigil.` becomes `sigilguard.` and the redundant
  # `.security.` segment is dropped - plus the exact-name exceptions (hashed
  # actor/identity/confirmation.actor, `content_hash` to the SP.01 subject
  # `payload.digest`, and the `<subject>.digest` family). The legacy
  # `sigil.registry.*` and `sigil.envelope.*` attributes are removed (SP.12).
  @attribute_map %{
    action: "sigilguard.action",
    action_digest: "sigilguard.action.digest",
    action_digest_error: "sigilguard.action.digest_error",
    actor: "sigilguard.actor.hash",
    anchor_digest: "sigilguard.audit.anchor.digest",
    anchor_storage: "sigilguard.audit.anchor.storage",
    anchor_store: "sigilguard.audit.anchor.store",
    anchor_uri_scheme: "sigilguard.audit.anchor.uri_scheme",
    bundle_digest: "sigilguard.trust_bundle.digest",
    bundle_id: "sigilguard.trust_bundle.id",
    card_digest: "sigilguard.agent_trust.card_digest",
    confirmation_actor: "sigilguard.confirmation.actor.hash",
    confirmation_expires_at: "sigilguard.confirmation.expires_at",
    confirmation_issued_at: "sigilguard.confirmation.issued_at",
    confirmation_nonce_hash: "sigilguard.confirmation.nonce_hash",
    confirmation_reason: "sigilguard.confirmation.reason",
    confirmation_status: "sigilguard.confirmation.status",
    content_hash: "sigilguard.payload.digest",
    detector: "sigilguard.boundary.adaptive.detector",
    dev: "sigilguard.trust_bundle.dev",
    error: "sigilguard.error.reason",
    error_reason: "sigilguard.error.reason",
    event_type: "sigilguard.audit.event_type",
    hit_count: "sigilguard.hit_count",
    hook_result: "sigilguard.boundary.hook.result",
    identity: "sigilguard.identity.hash",
    indicator_count: "sigilguard.indicator_count",
    indicator_ids: "sigilguard.indicator_ids",
    mcp_server: "sigilguard.mcp.server",
    module: "sigilguard.boundary.hook.module",
    origin: "sigilguard.origin",
    outcome: "sigilguard.outcome",
    patterns_checked: "sigilguard.scanner.patterns_checked",
    phase: "sigilguard.phase",
    pipeline: "sigilguard.scanner.pipeline",
    reason: "sigilguard.error.reason",
    release_status: "sigilguard.release.status",
    repo_policy_error: "sigilguard.repo_policy.error",
    repo_policy_rules: "sigilguard.repo_policy.rules",
    repo_policy_verdict: "sigilguard.repo_policy.verdict",
    repo_unmatched_paths: "sigilguard.repo_policy.unmatched_paths",
    resource_uri: "sigilguard.resource.uri",
    result: "sigilguard.audit.result",
    risk_level: "sigilguard.risk_level",
    root_version: "sigilguard.trust_bundle.root_version",
    runtime_input_error: "sigilguard.runtime_input_error",
    scanner_error: "sigilguard.scanner.error",
    scanner_validate: "sigilguard.scanner.validate",
    sequence: "sigilguard.trust_bundle.sequence",
    sink: "sigilguard.sink",
    statement_type: "sigilguard.agent_trust.statement_type",
    tool: "sigilguard.tool.name",
    trust_level: "sigilguard.trust_level",
    trust_required: "sigilguard.trust_required",
    trust_zone: "sigilguard.trust_zone",
    url: "url.full",
    verdict: "sigilguard.verdict"
  }

  # High-cardinality attributes (SP.05 D16): digests, hashes, opaque ids, and
  # URIs. Dropped unless `include_high_cardinality: true` so metric pipelines
  # stay bounded while span exporters can opt in.
  @high_cardinality_attributes [
    "sigilguard.action.digest",
    "sigilguard.actor.hash",
    "sigilguard.agent_trust.card_digest",
    "sigilguard.audit.anchor.digest",
    "sigilguard.confirmation.actor.hash",
    "sigilguard.confirmation.nonce_hash",
    "sigilguard.identity.hash",
    "sigilguard.payload.digest",
    "sigilguard.resource.uri",
    "sigilguard.trust_bundle.digest"
  ]

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
    attribute_opts = Keyword.take(opts, [:include_high_cardinality])

    :telemetry.attach_many(
      handler_id,
      events,
      fn event, measurements, metadata, _ ->
        attributes = otel_attributes(event, measurements, metadata, attribute_opts)
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
  (`url.full`). Every other attribute uses the `sigilguard.*` namespace (SP.05
  D16). High-cardinality attributes (digests, hashes, opaque ids, URIs) are
  dropped unless `include_high_cardinality: true` is passed in `opts`, so metric
  pipelines stay bounded while span exporters can opt in.
  """
  @spec otel_attributes(event_name(), map(), map(), keyword()) :: %{String.t() => otel_value()}
  def otel_attributes(event, measurements \\ %{}, metadata \\ %{}, opts \\ []) do
    %{
      "sigilguard.event" => event_name(event),
      "sigilguard.component" => component(event),
      "sigilguard.operation" => operation(event)
    }
    |> merge_measurements(measurements)
    |> merge_metadata(metadata)
    |> drop_high_cardinality(Keyword.get(opts, :include_high_cardinality, false))
  end

  defp merge_measurements(attributes, measurements) do
    measurements
    |> Enum.reduce(attributes, fn {key, value}, acc ->
      put_attribute(acc, "sigilguard.measurement.#{key}", value)
    end)
  end

  defp drop_high_cardinality(attributes, true), do: attributes

  defp drop_high_cardinality(attributes, _),
    do: Map.drop(attributes, @high_cardinality_attributes)

  defp merge_metadata(attributes, metadata) do
    Enum.reduce(metadata, attributes, fn {key, value}, acc ->
      case Map.fetch(@attribute_map, key) do
        {:ok, attribute} -> put_attribute(acc, attribute, value)
        :error -> acc
      end
    end)
  end

  defp put_attribute(attributes, _, nil), do: attributes

  defp put_attribute(attributes, key, value)
       when is_atom(value) and not is_boolean(value) and not is_nil(value) do
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

  defp attribute_value(value) when is_atom(value) and not is_boolean(value) and not is_nil(value),
    do: Atom.to_string(value)

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
