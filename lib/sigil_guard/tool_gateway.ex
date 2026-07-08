defmodule SigilGuard.ToolGateway do
  @moduledoc """
  Manifest-aware tool gateway entry points.

  This is the enforcement core for MCP-shaped tool calls and results. It
  combines capability-manifest checks, Agent Trust attestation verification,
  confirmation tokens, and `SigilGuard.Runtime.Gate` boundary decisions.
  `SigilGuard.MCP.Gateway` is the stable transport-facing facade that delegates
  here with MCP compatibility defaults.

  Use this module when the host owns request/result maps and wants the full
  policy surface. Use `SigilGuard.MCP.Gateway` when wiring an MCP adapter that
  wants JSON-RPC-compatible helper names and tuple shapes.

  ## Examples

      request = %{
        "method" => "tools/call",
        "params" => %{"name" => "read_file", "arguments" => %{"path" => "README.md"}}
      }

      context = [phase: :tool_request, origin: :model, sink: :tool, trust_level: :medium]

      decision = SigilGuard.ToolGateway.guard_request(request, context)
      decision.action in [:allow, :redact, :confirm, :quarantine, :block]
  """

  alias SigilGuard.Attestation
  alias SigilGuard.CapabilityManifest
  alias SigilGuard.Confirmation
  alias SigilGuard.Context
  alias SigilGuard.Decision
  alias SigilGuard.ToolGateway.Base, as: GatewayBase
  alias SigilGuard.TrustBundle

  @known_context_keys Map.keys(%Context{})
  @invalid_payload_field false
  @guard_metadata_keys [
    :_agent_trust,
    "_agent_trust",
    :_agent_confirmation,
    "_agent_confirmation",
    :confirmation_token,
    "confirmation_token"
  ]

  @type deny_reason ::
          :unknown_manifest
          | :invalid_manifest
          | :manifest_digest_mismatch
          | :manifest_expired
          | :schema_digest_mismatch
          | :suspicious_required_param
          | :resource_mismatch
          | :audience_mismatch
          | :token_passthrough_denied
          | :sandbox_required
          | :invalid_attestation
          | :invalid_payload
          | :invalid_confirmation_token
          | :missing_confirmation_key
          | :confirmation_failed

  @type attest_error :: Attestation.from_decision_error() | Attestation.sign_error()

  @type confirmation_issue_error ::
          :invalid_key
          | :not_confirmable
          | :invalid_ttl
          | :invalid_actor
          | :invalid_nonce
          | :invalid_now
          | :invalid_payload

  @doc """
  Guard a tool request using manifest checks before runtime policy evaluation.

  Supported options:

    * `:manifests` - map of tool name to pinned manifest, or `{pinned, observed}`
      tuples when the observed manifest is supplied separately.
    * `:require_manifest` - block unknown tools when no manifest resolves.
      Defaults to `true` when manifests are configured, otherwise `false`.
    * `:allow_suspicious_params` - explicit boundary-policy escape hatch for
      disclosed suspicious required parameters.
    * `:attestation` - `:off`, `:optional`, or `:required`.
    * `:confirmation` - `:honor` or `:off`; defaults to `:honor`.
    * `:confirmation_token`, `:confirmation_key`, `:consume_confirmation`,
      `:now` - forwarded to token verification.
  """
  @spec guard_request(term(), Context.t() | map() | keyword(), keyword()) :: Decision.t()
  def guard_request(request, context \\ %{}, opts \\ []) do
    payload = request_payload(request)
    request_context = request_context(request, context)

    with {:ok, capability} <- resolve_manifest(payload.tool, opts),
         :ok <- manifest_freshness(capability, opts),
         :ok <- passthrough_resource_audience(capability, opts),
         :ok <- require_sandbox(capability, request_context),
         :ok <- verify_inbound_attestation(request, payload, request_context, capability, opts) do
      request
      |> GatewayBase.guard_request(context, opts)
      |> put_manifest_metadata(capability)
      |> maybe_force_suspicious_confirmation(payload, request_context, capability, opts)
      |> maybe_apply_confirmation(payload, request_context, request, opts)
    else
      {:error, denial} -> deny(denial, payload, request_context)
    end
  end

  @doc """
  Verify an observed manifest against the configured manifest set.
  """
  @spec verify_manifest(String.t() | map(), keyword()) ::
          {:ok, CapabilityManifest.t()}
          | {:error,
             :unknown_manifest
             | :invalid_manifest
             | :manifest_expired
             | :manifest_digest_mismatch
             | :schema_digest_mismatch
             | :suspicious_required_param}
  def verify_manifest(observed, opts) when is_map(observed) do
    opts = Keyword.put(opts, :require_manifest, true)

    with {:ok, server} <- required_server(opts),
         {:ok, tool} <- observed_tool_name(observed),
         {:ok, pinned} <- resolve_manifest(tool, opts),
         :ok <- matching_server(server, pinned),
         {:ok, observed_manifest} <- observed_manifest(observed, pinned),
         :ok <- CapabilityManifest.verify(pinned, observed_manifest),
         {:ok, capability} <- manifest_struct(observed_manifest),
         :ok <- manifest_freshness(capability, opts) do
      {:ok, capability}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  def verify_manifest(tool, opts) when is_binary(tool) do
    opts = Keyword.put(opts, :require_manifest, true)

    with {:ok, capability} <- resolve_manifest(tool, opts),
         :ok <- maybe_match_server(capability, opts),
         :ok <- manifest_freshness(capability, opts) do
      {:ok, capability}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  def verify_manifest(_, _), do: {:error, :unknown_manifest}

  @doc """
  Verify a refreshed `tools/list` result after a `tools/list_changed` notice.
  """
  @spec verify_list_changed([map()], keyword()) ::
          {:ok, [CapabilityManifest.t()]} | {:error, deny_reason()}
  def verify_list_changed(observed_tools, opts) when is_list(observed_tools) do
    result =
      Enum.reduce_while(observed_tools, {:ok, []}, fn observed, {:ok, capabilities} ->
        case verify_manifest(observed, opts) do
          {:ok, capability} -> {:cont, {:ok, [capability | capabilities]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)

    case result do
      {:ok, capabilities} -> {:ok, Enum.reverse(capabilities)}
      {:error, reason} -> {:error, reason}
    end
  end

  def verify_list_changed(_, _), do: {:error, :invalid_manifest}

  @doc """
  Build and sign a `tool_request` attestation envelope.
  """
  @spec attest_request(Decision.t(), Context.t() | map() | keyword(), keyword()) ::
          {:ok, map()} | {:error, attest_error()}
  def attest_request(decision, context, opts \\ [])

  def attest_request(%Decision{} = decision, context, opts) when is_list(opts) do
    with {:ok, signer} <- required_attestation_signer(opts),
         opts <- attestation_opts(opts, :tool_request),
         {:ok, statement} <- Attestation.from_decision(decision, context, opts) do
      Attestation.sign(statement, signer, opts)
    end
  end

  def attest_request(_, _, _), do: {:error, :invalid_payload}

  @doc """
  Build and sign a `tool_result` attestation envelope.
  """
  @spec attest_result(Decision.t(), Context.t() | map() | keyword(), keyword()) ::
          {:ok, map()} | {:error, attest_error()}
  def attest_result(decision, context, opts \\ [])

  def attest_result(%Decision{} = decision, context, opts) when is_list(opts) do
    with {:ok, signer} <- required_attestation_signer(opts),
         opts <- attestation_opts(opts, :tool_result),
         {:ok, statement} <- Attestation.from_decision(decision, context, opts) do
      Attestation.sign(statement, signer, opts)
    end
  end

  def attest_result(_, _, _), do: {:error, :invalid_payload}

  @doc """
  Issue a confirmation token for a confirm-required tool request or result.

  Pass `direction: :request` (default) for tool calls and `direction: :result`
  for tool output. The token is bound to the same normalized payload and context
  shape used by `guard_request/3` or `guard_result/3`.
  """
  @spec issue_confirmation(
          term(),
          Context.t() | map() | keyword(),
          Decision.t(),
          binary(),
          keyword()
        ) ::
          {:ok, String.t()} | {:error, confirmation_issue_error()}
  def issue_confirmation(payload, context, %Decision{} = decision, key, opts \\ []) do
    with {:ok, direction} <- confirmation_direction(opts) do
      payload
      |> confirmation_payload(direction)
      |> Confirmation.issue(
        confirmation_context(payload, context, direction),
        decision,
        key,
        confirmation_issue_opts(opts)
      )
    end
  end

  @doc """
  Guard a tool result before it is returned to the model.
  """
  @spec guard_result(term(), Context.t() | map() | keyword(), keyword()) :: Decision.t()
  def guard_result(result, context \\ %{}, opts \\ []) do
    payload = result_payload(result)
    result_context = result_context(result, context)

    case request_action_digest(opts) do
      :ok ->
        result
        |> GatewayBase.guard_result(context, opts)
        |> put_result_binding_metadata(opts)
        |> maybe_apply_result_confirmation(payload, result_context, result, opts)

      {:error, reason} ->
        deny(reason, payload, result_context)
    end
  end

  @doc """
  Guard a tool request and return the JSON-RPC-compatible tuple shape.
  """
  @spec guarded_request(term(), Context.t() | map() | keyword(), keyword()) ::
          {:ok, Decision.t()} | {:error, map(), Decision.t()}
  def guarded_request(request, context \\ %{}, opts \\ []) do
    decision = guard_request(request, context, opts)

    if executable?(decision) do
      {:ok, decision}
    else
      {:error, response_for_decision(decision, request_id(request), opts), decision}
    end
  end

  @doc """
  Guard a tool result and return the JSON-RPC-compatible tuple shape.
  """
  @spec guarded_result(term(), Context.t() | map() | keyword(), keyword()) ::
          {:ok, map(), Decision.t()} | {:error, map(), Decision.t()}
  def guarded_result(result, context \\ %{}, opts \\ []) do
    decision = guard_result(result, context, opts)

    case decision.action do
      :allow ->
        {:ok, jsonrpc_result(result, request_id(result)), decision}

      :redact ->
        {:ok, GatewayBase.response_for_decision(decision, request_id(result), opts), decision}

      _ ->
        {:error, response_for_decision(decision, request_id(result), opts), decision}
    end
  end

  @doc "Return the JSON-RPC-compatible decision response."
  @spec response_for_decision(Decision.t(), term(), keyword()) :: map()
  def response_for_decision(%Decision{} = decision, id \\ nil, opts \\ []) do
    GatewayBase.response_for_decision(decision, id, opts)
  end

  @doc "Start the result stream sanitizer."
  @spec stream_result(Context.t() | map() | keyword(), keyword()) :: SigilGuard.Runtime.Stream.t()
  def stream_result(context \\ %{}, opts \\ []), do: GatewayBase.stream_result(context, opts)

  @doc "Guard one result stream chunk using the JSON-RPC-compatible tuple shape."
  @spec guarded_result_chunk(SigilGuard.Runtime.Stream.t(), String.t(), keyword()) ::
          {SigilGuard.Runtime.Stream.t(),
           {:ok, map() | nil, Decision.t()} | {:error, map(), Decision.t()}}
  def guarded_result_chunk(stream, chunk, opts \\ []),
    do: GatewayBase.guarded_result_chunk(stream, chunk, opts)

  @doc "Flush a guarded result stream using the JSON-RPC-compatible tuple shape."
  @spec finish_guarded_result_stream(SigilGuard.Runtime.Stream.t(), keyword()) ::
          {SigilGuard.Runtime.Stream.t(),
           {:ok, map() | nil, Decision.t()} | {:error, map(), Decision.t()}}
  def finish_guarded_result_stream(stream, opts \\ []),
    do: GatewayBase.finish_guarded_result_stream(stream, opts)

  defp resolve_manifest(nil, opts) do
    if require_manifest?(opts) do
      {:error, :unknown_manifest}
    else
      {:ok, nil}
    end
  end

  defp resolve_manifest(tool, opts) do
    case manifest_entry(tool, opts) do
      {:ok, entry} -> normalize_manifest_entry(tool, entry)
      :error -> maybe_allow_missing_manifest(opts)
    end
  end

  defp request_action_digest(opts) do
    case Keyword.fetch(opts, :request_action_digest) do
      {:ok, digest} when is_binary(digest) ->
        if digest =~ ~r/^[0-9a-f]{64}$/, do: :ok, else: {:error, :invalid_payload}

      {:ok, _} ->
        {:error, :invalid_payload}

      :error ->
        :ok
    end
  end

  defp confirmation_direction(opts) do
    case Keyword.get(opts, :direction, :request) do
      direction when direction in [:request, :result] -> {:ok, direction}
      _ -> {:error, :invalid_payload}
    end
  end

  defp confirmation_payload(payload, :request), do: request_payload(payload)
  defp confirmation_payload(payload, :result), do: result_payload(payload)

  defp confirmation_context(payload, context, :request), do: request_context(payload, context)
  defp confirmation_context(payload, context, :result), do: result_context(payload, context)

  defp confirmation_issue_opts(opts) do
    opts
    |> Keyword.take([:actor, :ttl_ms, :now, :nonce])
    |> maybe_put_issue_manifest(opts)
  end

  defp maybe_put_issue_manifest(issue_opts, opts) do
    cond do
      is_binary(Keyword.get(opts, :manifest)) ->
        Keyword.put(issue_opts, :manifest, Keyword.fetch!(opts, :manifest))

      match?(%CapabilityManifest{}, Keyword.get(opts, :manifest)) ->
        Keyword.put(issue_opts, :manifest, Keyword.fetch!(opts, :manifest).digest)

      is_binary(Keyword.get(opts, :manifest_digest)) ->
        Keyword.put(issue_opts, :manifest, Keyword.fetch!(opts, :manifest_digest))

      true ->
        issue_opts
    end
  end

  defp maybe_allow_missing_manifest(opts) do
    if require_manifest?(opts) do
      {:error, :unknown_manifest}
    else
      {:ok, nil}
    end
  end

  defp manifest_entry(tool, opts) do
    server = Keyword.get(opts, :server)
    manifests = Keyword.get(opts, :manifests, %{})
    trust_bundle = Keyword.get(opts, :trust_bundle)

    case fetch_manifest(manifests, tool, server) do
      {:ok, _} = entry -> entry
      :error -> fetch_bundle_manifest(trust_bundle, tool, server)
    end
  end

  defp require_manifest?(opts) do
    Keyword.get_lazy(opts, :require_manifest, fn ->
      Keyword.has_key?(opts, :manifests) or Keyword.has_key?(opts, :trust_bundle)
    end)
  end

  defp fetch_manifest(manifests, tool, server) when is_map(manifests) do
    atom_tool =
      try do
        {:ok, String.to_existing_atom(tool)}
      rescue
        ArgumentError -> :error
      end

    cond do
      present?(server) and Map.has_key?(manifests, {server, tool}) ->
        {:ok, Map.fetch!(manifests, {server, tool})}

      Map.has_key?(manifests, tool) ->
        {:ok, Map.fetch!(manifests, tool)}

      match?({:ok, _}, atom_tool) and Map.has_key?(manifests, elem(atom_tool, 1)) ->
        {:ok, Map.fetch!(manifests, elem(atom_tool, 1))}

      true ->
        :error
    end
  end

  defp fetch_manifest(_, _, _), do: :error

  defp fetch_bundle_manifest(%TrustBundle{} = bundle, tool, server) do
    bundle
    |> TrustBundle.tools()
    |> fetch_manifest_from_list(tool, server)
  end

  defp fetch_bundle_manifest(%{"tools" => tools}, tool, server) when is_list(tools),
    do: fetch_manifest_from_list(tools, tool, server)

  defp fetch_bundle_manifest(%{tools: tools}, tool, server) when is_list(tools),
    do: fetch_manifest_from_list(tools, tool, server)

  defp fetch_bundle_manifest(tools, tool, server) when is_list(tools),
    do: fetch_manifest_from_list(tools, tool, server)

  defp fetch_bundle_manifest(_, _, _), do: :error

  defp fetch_manifest_from_list(tools, tool, server) do
    Enum.find_value(tools, :error, fn entry ->
      with {:ok, capability} <- manifest_struct(entry),
           :ok <- matching_tool_name(tool, capability),
           :ok <- optional_matching_server(server, capability) do
        {:ok, entry}
      else
        _ -> false
      end
    end)
  end

  defp normalize_manifest_entry(tool, {pinned, observed}) do
    with {:ok, pinned} <- manifest_struct(pinned),
         :ok <- CapabilityManifest.verify(pinned, observed),
         {:ok, observed} <- manifest_struct(observed),
         :ok <- matching_tool_name(tool, observed) do
      {:ok, observed}
    end
  end

  defp normalize_manifest_entry(tool, manifest) do
    with {:ok, manifest} <- manifest_struct(manifest),
         :ok <- matching_tool_name(tool, manifest) do
      {:ok, manifest}
    end
  end

  defp manifest_struct(%CapabilityManifest{} = manifest), do: {:ok, manifest}

  defp manifest_struct(manifest) when is_map(manifest) do
    CapabilityManifest.new(manifest)
  end

  defp manifest_struct(_), do: {:error, :invalid_manifest}

  defp matching_tool_name(tool, %CapabilityManifest{name: tool}), do: :ok
  defp matching_tool_name(_, _), do: {:error, :manifest_digest_mismatch}

  defp required_server(opts) do
    case Keyword.get(opts, :server) do
      server when is_binary(server) and server != "" -> {:ok, server}
      _ -> {:error, :unknown_manifest}
    end
  end

  defp maybe_match_server(%CapabilityManifest{} = capability, opts) do
    case Keyword.get(opts, :server) do
      nil -> :ok
      server -> matching_server(server, capability)
    end
  end

  defp optional_matching_server(nil, _), do: :ok
  defp optional_matching_server("", _), do: :ok
  defp optional_matching_server(server, capability), do: matching_server(server, capability)

  defp matching_server(server, %CapabilityManifest{server: server}), do: :ok
  defp matching_server(_, _), do: {:error, :unknown_manifest}

  defp observed_tool_name(observed) do
    case observed_field(observed, "name", :name) do
      name when is_binary(name) and name != "" -> {:ok, name}
      _ -> {:error, :invalid_manifest}
    end
  end

  defp observed_manifest(observed, %CapabilityManifest{} = pinned) do
    if carried_manifest?(observed) do
      normalize_observed_carried_manifest(observed)
    else
      observed_list_manifest(observed, pinned)
    end
  end

  defp carried_manifest?(observed) do
    manifest_format = observed_field(observed, "manifest_format", :manifest_format)

    is_binary(manifest_format)
  end

  defp normalize_observed_carried_manifest(observed) do
    normalized =
      Map.new(observed, fn
        {:inputSchema, value} -> {"input_schema", value}
        {"inputSchema", value} -> {"input_schema", value}
        {:outputSchema, value} -> {"output_schema", value}
        {"outputSchema", value} -> {"output_schema", value}
        {key, value} when is_atom(key) -> {Atom.to_string(key), value}
        pair -> pair
      end)

    {:ok, normalized}
  end

  defp observed_list_manifest(observed, %CapabilityManifest{} = pinned) do
    with {:ok, name} <- required_observed_string(observed, "name", :name),
         {:ok, description} <- required_observed_string(observed, "description", :description),
         {:ok, input_schema} <- required_observed_map(observed, "inputSchema", :input_schema),
         {:ok, output_schema} <- optional_observed_map(observed, "outputSchema", :output_schema),
         {:ok, annotations} <- optional_observed_map(observed, "annotations", :annotations),
         :ok <- required_when_pinned("outputSchema", output_schema, pinned.output_schema),
         :ok <- required_when_pinned("annotations", annotations, pinned.annotations) do
      manifest =
        pinned
        |> pinned_manifest_map()
        |> Map.put("name", name)
        |> Map.put("description", description)
        |> Map.put("input_schema", input_schema)
        |> maybe_put_observed("output_schema", output_schema)
        |> maybe_put_observed("annotations", annotations)

      {:ok, manifest}
    end
  end

  defp pinned_manifest_map(%CapabilityManifest{} = pinned) do
    pinned
    |> Map.from_struct()
    |> Map.drop([
      :annotations_sha256,
      :description_sha256,
      :digest,
      :input_schema_sha256,
      :output_schema_sha256,
      :preimage
    ])
    |> Enum.reduce(%{}, fn
      {_, nil}, acc -> acc
      {key, value}, acc -> Map.put(acc, Atom.to_string(key), value)
    end)
  end

  defp observed_field(map, string_key, atom_key) do
    snake_key = Atom.to_string(atom_key)

    cond do
      Map.has_key?(map, string_key) -> Map.fetch!(map, string_key)
      Map.has_key?(map, snake_key) -> Map.fetch!(map, snake_key)
      Map.has_key?(map, atom_key) -> Map.fetch!(map, atom_key)
      true -> nil
    end
  end

  defp required_observed_string(map, string_key, atom_key) do
    case observed_field(map, string_key, atom_key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, :invalid_manifest}
    end
  end

  defp required_observed_map(map, string_key, atom_key) do
    case observed_field(map, string_key, atom_key) do
      value when is_map(value) -> {:ok, value}
      _ -> {:error, :invalid_manifest}
    end
  end

  defp optional_observed_map(map, string_key, atom_key) do
    case observed_field(map, string_key, atom_key) do
      nil -> {:ok, nil}
      value when is_map(value) -> {:ok, value}
      _ -> {:error, :invalid_manifest}
    end
  end

  defp required_when_pinned(_, value, pinned) when is_map(value) and is_map(pinned), do: :ok
  defp required_when_pinned(_, nil, nil), do: :ok
  defp required_when_pinned(_, value, nil) when is_map(value), do: :ok
  defp required_when_pinned(_, nil, pinned) when is_map(pinned), do: {:error, :invalid_manifest}

  defp maybe_put_observed(manifest, _, nil), do: manifest
  defp maybe_put_observed(manifest, key, value), do: Map.put(manifest, key, value)

  defp manifest_freshness(nil, _), do: :ok

  defp manifest_freshness(%CapabilityManifest{expires_at: expires_at}, opts) do
    with {:ok, expires_at, _} <- DateTime.from_iso8601(expires_at),
         {:ok, now} <- now(opts) do
      max_skew_ms = Keyword.get(opts, :max_skew_ms, 0)
      expires_at = DateTime.add(expires_at, max_skew_ms, :millisecond)

      if DateTime.compare(now, expires_at) == :gt do
        {:error, :manifest_expired}
      else
        :ok
      end
    else
      _ -> {:error, :invalid_manifest}
    end
  end

  defp now(opts) do
    case Keyword.get(opts, :now, DateTime.utc_now(:millisecond)) do
      %DateTime{} = now -> {:ok, now}
      _ -> {:error, :invalid_now}
    end
  end

  defp passthrough_resource_audience(nil, _), do: :ok

  defp passthrough_resource_audience(%CapabilityManifest{} = capability, opts) do
    with :ok <- token_passthrough(opts),
         :ok <- resource_match(capability, opts) do
      audience_match(capability, opts)
    end
  end

  defp token_passthrough(opts) do
    audience = Keyword.get(opts, :audience)
    self_resource = Keyword.get(opts, :self_resource)

    if present?(audience) and present?(self_resource) and
         audience_contains?(audience, self_resource) do
      {:error,
       {:token_passthrough_denied,
        %{
          audience: audience,
          self_resource: self_resource
        }}}
    else
      :ok
    end
  end

  defp resource_match(%CapabilityManifest{server: server}, opts) do
    case Keyword.get(opts, :resource) do
      nil -> :ok
      ^server -> :ok
      resource -> {:error, {:resource_mismatch, %{server: server, resource: resource}}}
    end
  end

  defp audience_match(%CapabilityManifest{server: server, audience: manifest_audience}, opts) do
    case Keyword.get(opts, :audience) do
      nil ->
        :ok

      audience ->
        accepted = [server | List.wrap(manifest_audience || [])]

        if Enum.any?(List.wrap(audience), &(&1 in accepted)) do
          :ok
        else
          {:error,
           {:audience_mismatch,
            %{
              audience: audience,
              accepted_audiences: accepted,
              server: server
            }}}
        end
    end
  end

  defp audience_contains?(audience, value), do: value in List.wrap(audience)
  defp present?(value), do: value not in [nil, ""]

  defp require_sandbox(nil, _), do: :ok
  defp require_sandbox(%CapabilityManifest{sandbox: %{"required" => false}}, _), do: :ok

  defp require_sandbox(
         %CapabilityManifest{name: tool, sandbox: %{"min_isolation" => min_isolation}},
         context
       ) do
    metadata = context.metadata
    sandbox_id = metadata[:sandbox_id] || metadata["sandbox_id"]
    isolation_level = metadata[:isolation_level] || metadata["isolation_level"]

    if present?(sandbox_id) and isolation_sufficient?(isolation_level, min_isolation) do
      :ok
    else
      {:error,
       {:sandbox_required,
        sandbox_denial_metadata(tool, min_isolation, isolation_level, sandbox_id)}}
    end
  end

  defp require_sandbox(%CapabilityManifest{name: tool}, context) do
    metadata = context.metadata
    sandbox_id = metadata[:sandbox_id] || metadata["sandbox_id"]
    isolation_level = metadata[:isolation_level] || metadata["isolation_level"]

    {:error, {:sandbox_required, sandbox_denial_metadata(tool, nil, isolation_level, sandbox_id)}}
  end

  defp sandbox_denial_metadata(tool, required_isolation, isolation_level, sandbox_id) do
    %{
      tool: tool,
      required_isolation: required_isolation,
      received_isolation: isolation_level,
      sandbox_id_present: present?(sandbox_id)
    }
  end

  defp isolation_sufficient?(received, required) do
    isolation_rank(received) >= isolation_rank(required)
  end

  defp isolation_rank("container"), do: 1
  defp isolation_rank("vm"), do: 2
  defp isolation_rank("remote_attested"), do: 3
  defp isolation_rank(_), do: 0

  defp verify_inbound_attestation(request, payload, context, capability, opts) do
    case Keyword.get(opts, :attestation, :off) do
      :off ->
        :ok

      :optional ->
        case Attestation.fetch(request) do
          {:ok, envelope} ->
            verify_attestation_envelope(envelope, payload, context, capability, opts)

          :error ->
            :ok
        end

      :required ->
        case Attestation.fetch(request) do
          {:ok, envelope} ->
            verify_attestation_envelope(envelope, payload, context, capability, opts)

          :error ->
            {:error, :invalid_attestation}
        end

      _ ->
        {:error, :invalid_attestation}
    end
  end

  defp verify_attestation_envelope(envelope, payload, context, capability, opts) do
    verify_opts =
      opts
      |> Keyword.take([:now, :max_skew_ms])
      |> Keyword.put(:payload, payload)
      |> Keyword.put(:context, context)
      |> maybe_put_manifest_digest(capability)

    case Attestation.verify(envelope, Keyword.get(opts, :trust_material, %{}), verify_opts) do
      {:ok, _} -> :ok
      {:error, _} -> {:error, :invalid_attestation}
    end
  end

  defp maybe_put_manifest_digest(opts, %CapabilityManifest{digest: digest})
       when is_binary(digest) do
    Keyword.put(opts, :manifest_digest, digest)
  end

  defp maybe_put_manifest_digest(opts, _), do: opts

  defp required_attestation_signer(opts) do
    case Keyword.get(opts, :signer) do
      signer when is_atom(signer) -> {:ok, signer}
      _ -> {:error, :invalid_signer}
    end
  end

  defp attestation_opts(opts, statement_type) do
    opts
    |> Keyword.put(:statement_type, statement_type)
    |> normalize_attestation_manifest()
  end

  defp normalize_attestation_manifest(opts) do
    case Keyword.get(opts, :manifest) do
      %CapabilityManifest{} = capability ->
        opts
        |> Keyword.put(:manifest_digest, capability.digest)
        |> maybe_put_output_schema_sha256(capability.output_schema_sha256)

      _ ->
        opts
    end
  end

  defp maybe_put_output_schema_sha256(opts, digest) when is_binary(digest),
    do: Keyword.put_new(opts, :output_schema_sha256, digest)

  defp maybe_put_output_schema_sha256(opts, _), do: opts

  defp maybe_force_suspicious_confirmation(%Decision{verdict: :blocked} = decision, _, _, _, _) do
    decision
  end

  defp maybe_force_suspicious_confirmation(decision, _, _, nil, _), do: decision

  defp maybe_force_suspicious_confirmation(
         %Decision{} = decision,
         payload,
         context,
         %CapabilityManifest{suspicious_params: [_ | _]} = capability,
         opts
       ) do
    if Keyword.get(opts, :allow_suspicious_params, false) do
      decision
    else
      suspicious_confirmation(decision, payload, context, capability)
    end
  end

  defp maybe_force_suspicious_confirmation(%Decision{} = decision, _, _, _, _), do: decision

  defp suspicious_confirmation(%Decision{} = decision, payload, context, capability) do
    action_digest =
      case Confirmation.fetch_action_digest(payload, context) do
        {:ok, digest} -> digest
        {:error, _} -> nil
      end

    metadata =
      Map.merge(decision.audit_metadata, %{
        verdict: :confirm,
        action: :confirm,
        deny_reason: :suspicious_required_param,
        manifest_digest: capability.digest,
        manifest_name: capability.name,
        suspicious_params: capability.suspicious_params,
        action_digest: action_digest
      })

    %{
      decision
      | verdict: {:confirm, "suspicious_required_param"},
        action: :confirm,
        reason: "Capability manifest discloses suspicious required parameters",
        audit_metadata: metadata
    }
  end

  defp maybe_apply_confirmation(
         %Decision{verdict: {:confirm, _}} = decision,
         payload,
         context,
         token_source,
         opts
       ) do
    case confirmation_token(opts, token_source) do
      {:ok, token} ->
        verify_confirmation(decision, payload, context, token, opts)

      :off ->
        decision

      :error ->
        decision

      {:error, reason} ->
        confirmation_failure_decision(decision, reason)
    end
  end

  defp maybe_apply_confirmation(%Decision{} = decision, _, _, _, _), do: decision

  defp maybe_apply_result_confirmation(
         %Decision{verdict: {:confirm, _}} = decision,
         payload,
         context,
         token_source,
         opts
       ) do
    decision
    |> maybe_apply_confirmation(payload, context, token_source, opts)
    |> release_confirmed_result()
  end

  defp maybe_apply_result_confirmation(%Decision{} = decision, _, _, _, _), do: decision

  defp confirmation_token(opts, token_source) do
    case Keyword.get(opts, :confirmation, :honor) do
      :off ->
        :off

      :honor ->
        confirmation_token_option(opts, token_source)

      true ->
        :error

      token when is_binary(token) ->
        {:ok, token}

      _ ->
        {:error, :invalid_confirmation_token}
    end
  end

  defp confirmation_token_option(opts, token_source) do
    case Keyword.fetch(opts, :confirmation_token) do
      {:ok, token} when is_binary(token) -> {:ok, token}
      {:ok, _} -> {:error, :invalid_confirmation_token}
      :error -> fetch_confirmation_token(token_source)
    end
  end

  defp fetch_confirmation_token(token_source) do
    case Attestation.fetch_confirmation(token_source) do
      {:ok, token} -> {:ok, token}
      :error -> fetch_nested_confirmation_token(token_source)
    end
  end

  defp fetch_nested_confirmation_token(token_source) when is_map(token_source) do
    case first_present_payload_term(token_source, confirmation_token_paths()) do
      {:ok, token} when is_binary(token) -> {:ok, token}
      {:ok, _} -> {:error, :invalid_confirmation_token}
      :not_found -> :error
    end
  end

  defp verify_confirmation(decision, payload, context, token, opts) do
    with {:ok, key} <- confirmation_key(opts),
         {:ok, claims} <-
           Confirmation.verify(token, payload, context, key, confirmation_opts(decision, opts)) do
      confirmed_decision(decision, claims)
    else
      {:error, reason} -> confirmation_failure_decision(decision, reason)
    end
  end

  defp confirmation_key(opts) do
    case Keyword.get(opts, :confirmation_key) do
      key when is_binary(key) -> {:ok, key}
      _ -> {:error, :missing_confirmation_key}
    end
  end

  defp confirmation_opts(decision, opts) do
    opts
    |> Keyword.take([:now])
    |> Keyword.put(:consume, Keyword.get(opts, :consume_confirmation, true))
    |> maybe_put_confirmation_manifest(decision)
  end

  defp maybe_put_confirmation_manifest(opts, %Decision{
         audit_metadata: %{manifest_digest: digest}
       })
       when is_binary(digest) do
    Keyword.put(opts, :manifest, digest)
  end

  defp maybe_put_confirmation_manifest(opts, _), do: opts

  defp confirmed_decision(%Decision{} = decision, claims) do
    metadata =
      Map.merge(decision.audit_metadata, %{
        verdict: :allowed,
        action: :allow,
        confirmation_status: :accepted,
        confirmation_actor: claims["actor"],
        confirmation_nonce_hash: hash_text(claims["nonce"]),
        confirmation_issued_at: claims["issued_at"],
        confirmation_expires_at: claims["expires_at"]
      })

    %{
      decision
      | verdict: :allowed,
        action: :allow,
        reason: "Confirmation token accepted",
        audit_metadata: metadata
    }
  end

  defp release_confirmed_result(
         %Decision{
           verdict: :allowed,
           audit_metadata: %{quarantine_status: :quarantined} = metadata
         } = decision
       ) do
    released_metadata =
      Map.merge(metadata, %{
        action: :redact,
        release_status: :confirmed_sanitized
      })

    %{
      decision
      | action: :redact,
        reason: "Confirmation token accepted; sanitized result released",
        audit_metadata: released_metadata
    }
  end

  defp release_confirmed_result(%Decision{} = decision), do: decision

  defp confirmation_failure_decision(%Decision{} = decision, reason) do
    metadata =
      Map.merge(decision.audit_metadata, %{
        verdict: :blocked,
        action: :block,
        risk_level: :high,
        deny_reason: :confirmation_failed,
        confirmation_status: :invalid,
        confirmation_reason: reason
      })

    %{
      decision
      | verdict: :blocked,
        action: :block,
        reason: "Tool gateway confirmation verification failed: #{format_reason(reason)}",
        risk_level: :high,
        audit_metadata: metadata
    }
  end

  defp deny(denial, payload, context) do
    {reason, denial_metadata} = denial_metadata(denial)
    content_hash = hash_text(payload.text || "")

    %Decision{
      verdict: :blocked,
      action: :block,
      reason: "Tool gateway denied request: #{format_reason(reason)}",
      phase: context.phase,
      risk_level: :high,
      trust_level: context.trust_level,
      hits: [],
      indicators: [],
      sanitized_text: nil,
      content_hash: content_hash,
      audit_metadata:
        %{
          phase: context.phase,
          actor: context.actor,
          identity: context.identity,
          origin: context.origin,
          sink: context.sink,
          tool: context.tool,
          mcp_server: context.mcp_server,
          resource_uri: context.resource_uri,
          trust_zone: context.trust_zone,
          trust_level: context.trust_level,
          risk_level: :high,
          verdict: :blocked,
          action: :block,
          deny_reason: reason,
          hit_count: 0,
          indicator_count: 0,
          content_hash: content_hash
        }
        |> Map.merge(denial_metadata)
    }
  end

  defp denial_metadata({reason, metadata}) when is_atom(reason) and is_map(metadata) do
    {reason, Map.put(metadata, :deny_reason, reason)}
  end

  defp denial_metadata(reason) when is_atom(reason), do: {reason, %{deny_reason: reason}}

  defp put_manifest_metadata(%Decision{} = decision, nil), do: decision

  defp put_manifest_metadata(%Decision{} = decision, %CapabilityManifest{} = capability) do
    metadata =
      Map.merge(decision.audit_metadata, %{
        manifest_digest: capability.digest,
        manifest_name: capability.name,
        suspicious_params: capability.suspicious_params
      })

    %{decision | audit_metadata: metadata}
  end

  defp put_result_binding_metadata(%Decision{} = decision, opts) do
    metadata =
      decision.audit_metadata
      |> maybe_put_request_action_digest(Keyword.get(opts, :request_action_digest))
      |> Map.put(:scanner_summary, %{
        hit_count: length(decision.hits),
        indicator_count: length(decision.indicators),
        indicator_ids: Enum.map(decision.indicators, & &1.id)
      })
      |> Map.put(:quarantine_status, quarantine_status(decision))

    %{decision | audit_metadata: metadata}
  end

  defp maybe_put_request_action_digest(metadata, digest) when is_binary(digest),
    do: Map.put(metadata, :request_action_digest, digest)

  defp maybe_put_request_action_digest(metadata, _), do: metadata

  defp quarantine_status(%Decision{action: :quarantine}), do: :quarantined
  defp quarantine_status(%Decision{effect: :quarantine}), do: :quarantined
  defp quarantine_status(%Decision{verdict: {:confirm, _}, indicators: [_ | _]}), do: :confirm
  defp quarantine_status(%Decision{indicators: [_ | _]}), do: :suspicious
  defp quarantine_status(_), do: :safe

  defp request_context(request, context) do
    tool = tool_name(request)
    action = action_name(request)

    %{
      phase: :tool_request,
      origin: :model,
      sink: :tool,
      tool: context_field(tool),
      action: action_field(action, tool),
      mcp_server: context_field(mcp_server(request))
    }
    |> Map.merge(context_overrides(context))
    |> Context.new()
  end

  defp result_context(result, context) do
    tool = tool_name(result)
    action = action_name(result)

    %{
      phase: :tool_result,
      origin: :tool,
      sink: :model,
      tool: context_field(tool),
      action: action_field(action, tool),
      mcp_server: context_field(mcp_server(result))
    }
    |> Map.merge(context_overrides(context))
    |> Context.new()
  end

  defp request_payload(request) do
    payload = strip_guard_metadata(request)
    tool = tool_name(payload)
    action = action_name(payload)

    %{
      tool: context_field(tool),
      action: action_field(action, tool),
      text: text_payload(payload)
    }
  end

  defp result_payload(result) do
    payload = strip_guard_metadata(result)
    tool = tool_name(payload)
    action = action_name(payload)

    %{
      tool: context_field(tool),
      action: action_field(action, tool),
      text: text_payload(payload)
    }
  end

  defp strip_guard_metadata(value) when is_map(value) do
    value
    |> Map.drop(@guard_metadata_keys)
    |> strip_params_metadata(:params)
    |> strip_params_metadata("params")
  end

  defp strip_guard_metadata(value), do: value

  defp strip_params_metadata(payload, params_key) do
    case Map.get(payload, params_key) do
      params when is_map(params) ->
        Map.put(payload, params_key, Map.drop(params, @guard_metadata_keys))

      _ ->
        payload
    end
  end

  defp text_payload(payload) when is_map(payload), do: joined_strings(payload)
  defp text_payload(payload), do: Context.text(payload) || joined_strings(payload)

  defp joined_strings(payload) do
    payload
    |> collect_strings()
    |> Enum.reverse()
    |> Enum.join("\n")
  end

  defp collect_strings(value), do: collect_strings(value, [])
  defp collect_strings(value, acc) when is_binary(value), do: [value | acc]

  defp collect_strings(value, acc) when is_list(value),
    do: Enum.reduce(value, acc, &collect_strings/2)

  defp collect_strings(value, acc) when is_map(value) do
    value
    |> Map.values()
    |> Enum.reduce(acc, &collect_strings/2)
  end

  defp collect_strings(_, acc), do: acc

  defp tool_name(payload) do
    first_payload_value(payload, [
      [:tool],
      ["tool"],
      [:name],
      ["name"],
      [:params, :name],
      [:params, "name"],
      ["params", :name],
      ["params", "name"]
    ])
  end

  defp action_name(payload) do
    first_payload_value(payload, [
      [:action],
      ["action"],
      [:tool],
      ["tool"],
      [:name],
      ["name"],
      [:params, :name],
      [:params, "name"],
      ["params", :name],
      ["params", "name"],
      [:method],
      ["method"]
    ])
  end

  defp mcp_server(payload) do
    first_payload_value(payload, [
      [:mcp_server],
      ["mcp_server"],
      [:server],
      ["server"],
      [:params, :server],
      [:params, "server"],
      ["params", :server],
      ["params", "server"]
    ])
  end

  defp first_payload_value(payload, paths) when is_map(payload) do
    Enum.reduce_while(paths, nil, fn path, nil ->
      case fetch_path(payload, path) do
        {:ok, nil} -> {:cont, nil}
        {:ok, value} when is_binary(value) -> {:halt, value}
        {:ok, _} -> {:halt, @invalid_payload_field}
        :error -> {:cont, nil}
      end
    end)
  end

  defp first_payload_value(_, _), do: nil

  defp request_id(payload) when is_map(payload) do
    first_payload_term(payload, [
      [:id],
      ["id"],
      [:request_id],
      ["request_id"]
    ])
  end

  defp request_id(_), do: nil

  defp jsonrpc_result(%{"jsonrpc" => _, "id" => id, "result" => result}, _) do
    %{"jsonrpc" => "2.0", "id" => id, "result" => result}
  end

  defp jsonrpc_result(%{jsonrpc: _, id: id, result: result}, _) do
    %{"jsonrpc" => "2.0", "id" => id, "result" => result}
  end

  defp jsonrpc_result(result, id) do
    %{"jsonrpc" => "2.0", "id" => id, "result" => result}
  end

  defp confirmation_token_paths do
    [
      [:_agent_confirmation],
      ["_agent_confirmation"],
      [:confirmation_token],
      ["confirmation_token"],
      [:params, :_agent_confirmation],
      [:params, "_agent_confirmation"],
      [:params, :confirmation_token],
      [:params, "confirmation_token"],
      ["params", :_agent_confirmation],
      ["params", "_agent_confirmation"],
      ["params", :confirmation_token],
      ["params", "confirmation_token"]
    ]
  end

  defp first_payload_term(payload, paths) when is_map(payload) do
    Enum.find_value(paths, &get_in(payload, &1))
  end

  defp first_present_payload_term(payload, paths) when is_map(payload) do
    Enum.reduce_while(paths, :not_found, fn path, :not_found ->
      case fetch_payload_path(payload, path) do
        {:ok, value} -> {:halt, {:ok, value}}
        :error -> {:cont, :not_found}
      end
    end)
  end

  defp fetch_payload_path(payload, []), do: {:ok, payload}

  defp fetch_payload_path(payload, [key | rest]) when is_map(payload) do
    case Map.fetch(payload, key) do
      {:ok, value} -> fetch_payload_path(value, rest)
      :error -> :error
    end
  end

  defp fetch_payload_path(_, _), do: :error

  defp fetch_path(payload, [key]) when is_map(payload), do: Map.fetch(payload, key)

  defp fetch_path(payload, [key | rest]) when is_map(payload) do
    case Map.fetch(payload, key) do
      {:ok, value} when is_map(value) -> fetch_path(value, rest)
      {:ok, nil} -> :error
      {:ok, _} -> {:ok, @invalid_payload_field}
      :error -> :error
    end
  end

  defp fetch_path(_, _), do: :error

  defp action_field(action, tool) do
    if invalid_payload_field?(action) or invalid_payload_field?(tool),
      do: @invalid_payload_field,
      else: action
  end

  defp context_field(value) do
    if invalid_payload_field?(value), do: nil, else: value
  end

  defp invalid_payload_field?(@invalid_payload_field), do: true
  defp invalid_payload_field?(_), do: false

  defp executable?(%Decision{verdict: :allowed, action: action}), do: action in [:allow, :redact]
  defp executable?(%Decision{}), do: false

  defp context_overrides(%Context{} = context), do: Map.from_struct(context)

  defp context_overrides(context) when is_list(context) do
    context
    |> Map.new()
    |> context_overrides()
  end

  defp context_overrides(context) when is_map(context) do
    Map.new(context, fn {key, value} -> {known_context_key(key), value} end)
  end

  defp context_overrides(_), do: %{}

  defp known_context_key(key) when is_atom(key), do: key

  defp known_context_key(key) when is_binary(key) do
    atom_key = String.to_existing_atom(key)

    if atom_key in @known_context_keys, do: atom_key, else: key
  rescue
    ArgumentError -> key
  end

  defp format_reason(reason) when is_atom(reason), do: Atom.to_string(reason)
  defp hash_text(text), do: Base.encode16(:crypto.hash(:sha256, text), case: :lower)
end
