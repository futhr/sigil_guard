defmodule SigilGuard.ToolGateway do
  @moduledoc """
  Manifest-aware tool gateway entry points.

  `SigilGuard.MCP.Gateway` remains the transport-facing MCP adapter. This
  module layers capability-manifest checks above it so manifest failures happen
  before runtime execution.
  """

  alias SigilGuard.CapabilityManifest
  alias SigilGuard.Confirmation
  alias SigilGuard.Context
  alias SigilGuard.Decision
  alias SigilGuard.MCP

  @known_context_keys Map.keys(%Context{})
  @invalid_payload_field false
  @guard_metadata_keys [
    :_agent_trust,
    "_agent_trust",
    :_agent_confirmation,
    "_agent_confirmation",
    :_sigil,
    "_sigil",
    :_sigil_confirmation,
    "_sigil_confirmation",
    :confirmation_token,
    "confirmation_token"
  ]

  @type deny_reason ::
          :unknown_manifest
          | :invalid_manifest
          | :manifest_digest_mismatch
          | :schema_digest_mismatch
          | :suspicious_required_param
          | :missing_sandbox
          | :invalid_confirmation_token
          | :missing_confirmation_key
          | :confirmation_failed

  @doc """
  Guard a tool request using manifest checks before runtime policy evaluation.

  Supported options:

    * `:manifests` - map of tool name to pinned manifest, or `{pinned, observed}`
      tuples when the observed manifest is supplied separately.
    * `:require_manifest` - block unknown tools when no manifest resolves.
    * `:allow_suspicious_params` - explicit boundary-policy escape hatch for
      disclosed suspicious required parameters.
    * `:confirmation` - confirmation token to apply to a confirmation decision.
    * `:confirmation_key`, `:consume_confirmation`, `:now` - forwarded to token
      verification.
  """
  @spec guard_request(term(), Context.t() | map() | keyword(), keyword()) :: Decision.t()
  def guard_request(request, context \\ %{}, opts \\ []) do
    payload = request_payload(request)
    request_context = request_context(request, context)

    with {:ok, capability} <- resolve_manifest(payload.tool, opts),
         :ok <- require_sandbox(capability) do
      request
      |> MCP.Gateway.guard_request(context, opts)
      |> put_manifest_metadata(capability)
      |> maybe_force_suspicious_confirmation(payload, request_context, capability, opts)
      |> maybe_apply_confirmation(payload, request_context, opts)
    else
      {:error, reason} -> deny(reason, payload, request_context)
    end
  end

  @doc """
  Verify an observed manifest against the configured manifest set.
  """
  @spec verify_manifest(String.t(), keyword()) ::
          {:ok, CapabilityManifest.t()}
          | {:error,
             :unknown_manifest
             | :invalid_manifest
             | :manifest_digest_mismatch
             | :schema_digest_mismatch
             | :suspicious_required_param}
  def verify_manifest(tool, opts) when is_binary(tool) do
    opts = Keyword.put(opts, :require_manifest, true)

    resolve_manifest(tool, opts)
  end

  def verify_manifest(_, _), do: {:error, :unknown_manifest}

  defp resolve_manifest(nil, opts) do
    if Keyword.get(opts, :require_manifest, false) do
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

  defp maybe_allow_missing_manifest(opts) do
    if Keyword.get(opts, :require_manifest, false) do
      {:error, :unknown_manifest}
    else
      {:ok, nil}
    end
  end

  defp manifest_entry(tool, opts) do
    opts
    |> Keyword.get(:manifests, %{})
    |> fetch_manifest(tool)
  end

  defp fetch_manifest(manifests, tool) when is_map(manifests) do
    atom_tool =
      try do
        {:ok, String.to_existing_atom(tool)}
      rescue
        ArgumentError -> :error
      end

    cond do
      Map.has_key?(manifests, tool) ->
        {:ok, Map.fetch!(manifests, tool)}

      match?({:ok, _}, atom_tool) and Map.has_key?(manifests, elem(atom_tool, 1)) ->
        {:ok, Map.fetch!(manifests, elem(atom_tool, 1))}

      true ->
        :error
    end
  end

  defp fetch_manifest(_, _), do: :error

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

  defp require_sandbox(nil), do: :ok
  defp require_sandbox(%CapabilityManifest{sandbox: %{"required" => true}}), do: :ok
  defp require_sandbox(%CapabilityManifest{}), do: {:error, :missing_sandbox}

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
         opts
       ) do
    case confirmation_token(opts) do
      {:ok, token} ->
        verify_confirmation(decision, payload, context, token, opts)

      :error ->
        decision

      {:error, reason} ->
        confirmation_failure_decision(decision, reason)
    end
  end

  defp maybe_apply_confirmation(%Decision{} = decision, _, _, _), do: decision

  defp confirmation_token(opts) do
    case Keyword.fetch(opts, :confirmation) do
      {:ok, true} -> :error
      {:ok, token} when is_binary(token) -> {:ok, token}
      {:ok, _} -> {:error, :invalid_confirmation_token}
      :error -> :error
    end
  end

  defp verify_confirmation(decision, payload, context, token, opts) do
    with {:ok, key} <- confirmation_key(opts),
         {:ok, claims} <-
           Confirmation.verify(token, payload, context, key, confirmation_opts(opts)) do
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

  defp confirmation_opts(opts) do
    opts
    |> Keyword.take([:now])
    |> Keyword.put(:consume, Keyword.get(opts, :consume_confirmation, true))
  end

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

  defp deny(reason, payload, context) do
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
      audit_metadata: %{
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
    }
  end

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
