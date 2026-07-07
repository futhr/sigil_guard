defmodule SigilGuard.Attestation.Digest do
  @moduledoc """
  Digest computation for SigilGuard agent-trust Statements.

  Digests are lowercase SHA-256 hex strings. Structured preimages are
  normalized according to the trust profile and encoded with RFC 8785 JCS
  before hashing.
  """

  alias SigilGuard.Attestation
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.Context

  @sha256_regex ~r/^[0-9a-f]{64}$/
  @statement_types ~w(
    tool_request
    tool_result
    model_ingress
    model_egress
    repo_change
    release
    agent_request
    agent_response
  )a

  @type statement_type ::
          :tool_request
          | :tool_result
          | :model_ingress
          | :model_egress
          | :repo_change
          | :release
          | :agent_request
          | :agent_response

  @type error_reason :: :invalid_payload | :unsupported_number_range | :unknown_statement_type

  @doc """
  Normalize a JSON-shaped value for digest preimages.

  Atom keys and atom values are converted to strings, booleans and nil retain
  their JSON meanings in lists, and map entries with nil values are omitted.
  Duplicate keys after normalization fail with `:invalid_payload`.
  """
  @spec normalize(term()) :: {:ok, term()} | {:error, :invalid_payload}
  def normalize(value), do: normalize_value(value)

  @doc """
  Compute the payload digest for any SP.01 payload class.
  """
  @spec payload_digest(term()) :: {:ok, String.t()} | {:error, error_reason()}
  def payload_digest(payload) when is_binary(payload) do
    if String.valid?(payload) do
      {:ok, sha256_hex(payload)}
    else
      {:error, :invalid_payload}
    end
  end

  def payload_digest(payload) when is_map(payload) do
    payload
    |> Attestation.strip_metadata()
    |> normalized_jcs_digest()
  end

  def payload_digest(payload) when is_list(payload) do
    payload
    |> Attestation.strip_metadata()
    |> normalized_jcs_digest()
  end

  def payload_digest(_), do: {:error, :invalid_payload}

  @doc """
  Compute the shared SP.01 context digest for a statement type.
  """
  @spec context_digest(statement_type(), Context.t() | map() | keyword()) ::
          {:ok, String.t()} | {:error, error_reason()}
  def context_digest(statement_type, context) do
    with {:ok, preimage} <- context_preimage(statement_type, context) do
      normalized_jcs_digest(preimage)
    end
  end

  @doc """
  Return the shared SP.01 context digest preimage for a statement type.
  """
  @spec context_preimage(statement_type(), Context.t() | map() | keyword()) ::
          {:ok, map()} | {:error, error_reason()}
  def context_preimage(statement_type, context) when statement_type in @statement_types do
    context_map = context_map(context)

    %{
      "statement_type" => Atom.to_string(statement_type),
      "trust_level" => context_map.trust_level,
      "phase" => context_map.phase,
      "origin" => context_map.origin,
      "sink" => context_map.sink,
      "trust_zone" => context_map.trust_zone,
      "intended_audience" => context_map.intended_audience
    }
    |> maybe_put("actor", context_map.actor)
    |> maybe_put("identity", context_map.identity)
    |> maybe_put("source", context_map.source)
    |> maybe_put("mcp_server", context_map.mcp_server)
    |> maybe_put("tool", context_map.tool)
    |> maybe_put("resource_uri", context_map.resource_uri)
    |> maybe_put("sandbox_id", context_extra(context, "sandbox_id"))
    |> maybe_put("isolation_level", context_extra(context, "isolation_level"))
    |> ok()
  end

  def context_preimage(_, _), do: {:error, :unknown_statement_type}

  @doc """
  Compute the SP.01 action digest for a statement type.
  """
  @spec action_digest(statement_type(), term(), Context.t() | map() | keyword(), keyword()) ::
          {:ok, String.t()} | {:error, error_reason()}
  def action_digest(statement_type, payload, context, opts \\ []) do
    with {:ok, preimage} <- action_preimage(statement_type, payload, context, opts) do
      normalized_jcs_digest(preimage)
    end
  end

  @doc """
  Return the SP.01 action digest preimage for a statement type.
  """
  @spec action_preimage(statement_type(), term(), Context.t() | map() | keyword(), keyword()) ::
          {:ok, map()} | {:error, error_reason()}
  def action_preimage(statement_type, payload, context, opts \\ [])

  def action_preimage(:tool_request, payload, context, _) do
    with {:ok, payload} <- normalized_payload_map(payload),
         {:ok, tool} <- tool_request_tool(payload, context) do
      %{"statement_type" => "tool_request", "tool" => tool}
      |> maybe_put("method", Map.get(payload, "method"))
      |> maybe_put("arguments", tool_request_arguments(payload))
      |> ok()
    end
  end

  def action_preimage(:tool_result, payload, context, opts) do
    with {:ok, payload} <- normalized_payload_map(payload),
         {:ok, tool} <- required_context_field(context, "tool"),
         {:ok, request_action_digest} <- request_action_digest(opts) do
      %{
        "statement_type" => "tool_result",
        "tool" => tool,
        "request_action_digest" => request_action_digest
      }
      |> maybe_put("method", Map.get(payload, "method"))
      |> ok()
    end
  end

  def action_preimage(:model_ingress, _, context, _) do
    with {:ok, origin} <- required_context_field(context, "origin") do
      %{"statement_type" => "model_ingress", "origin" => origin}
      |> maybe_put("source", context_extra_or_known(context, "source"))
      |> maybe_put("resource_uri", context_extra_or_known(context, "resource_uri"))
      |> ok()
    end
  end

  def action_preimage(:model_egress, _, context, _) do
    with {:ok, sink} <- required_context_field(context, "sink"),
         {:ok, intended_audience} <- required_context_field(context, "intended_audience") do
      %{
        "statement_type" => "model_egress",
        "sink" => sink,
        "intended_audience" => intended_audience
      }
      |> maybe_put("resource_uri", context_extra_or_known(context, "resource_uri"))
      |> ok()
    end
  end

  def action_preimage(:repo_change, payload, _, _) do
    with {:ok, payload} <- normalized_payload_map(payload),
         {:ok, repository} <- required_payload_field(payload, "repository"),
         {:ok, operation} <- required_payload_field(payload, "operation"),
         {:ok, paths} <- repo_paths(payload) do
      %{
        "statement_type" => "repo_change",
        "repository" => repository,
        "operation" => operation,
        "paths" => paths
      }
      |> maybe_put("ref", Map.get(payload, "ref"))
      |> ok()
    end
  end

  def action_preimage(:release, payload, _, _) do
    with {:ok, payload} <- normalized_payload_map(payload),
         {:ok, package} <- required_payload_field(payload, "package"),
         {:ok, version} <- required_payload_field(payload, "version"),
         {:ok, artifacts} <- release_artifacts(payload) do
      {:ok,
       %{
         "statement_type" => "release",
         "package" => package,
         "version" => version,
         "artifacts" => artifacts
       }}
    end
  end

  def action_preimage(:agent_request, payload, _, _) do
    with {:ok, payload} <- normalized_payload_map(payload),
         {:ok, peer_agent} <- required_payload_field(payload, "peer_agent"),
         {:ok, capability} <- required_payload_field(payload, "capability") do
      %{
        "statement_type" => "agent_request",
        "peer_agent" => peer_agent,
        "capability" => capability
      }
      |> maybe_put("arguments", Map.get(payload, "arguments"))
      |> ok()
    end
  end

  def action_preimage(:agent_response, payload, _, opts) do
    with {:ok, payload} <- normalized_payload_map(payload),
         {:ok, peer_agent} <- required_payload_field(payload, "peer_agent"),
         {:ok, capability} <- required_payload_field(payload, "capability"),
         {:ok, request_action_digest} <- request_action_digest(opts) do
      {:ok,
       %{
         "statement_type" => "agent_response",
         "peer_agent" => peer_agent,
         "capability" => capability,
         "request_action_digest" => request_action_digest
       }}
    end
  end

  def action_preimage(_, _, _, _), do: {:error, :unknown_statement_type}

  @doc """
  Compute action, payload, context, and applicable manifest digests.
  """
  @spec digests(statement_type(), term(), map() | keyword(), keyword()) ::
          {:ok, %{required(String.t()) => String.t()}} | {:error, error_reason()}
  def digests(statement_type, payload, context, opts \\ []) do
    with {:ok, action} <- action_digest(statement_type, payload, context, opts),
         {:ok, payload_digest} <- payload_digest(payload),
         {:ok, context_digest} <- context_digest(statement_type, context),
         {:ok, manifest} <- maybe_manifest_digest(statement_type, opts) do
      %{"action" => action, "payload" => payload_digest, "context" => context_digest}
      |> maybe_put("manifest", manifest)
      |> ok()
    end
  end

  @doc """
  Compute a manifest digest from a verified manifest value.
  """
  @spec manifest_digest(term()) :: {:ok, String.t()} | {:error, error_reason()}
  def manifest_digest(manifest) when is_binary(manifest), do: payload_digest(manifest)
  def manifest_digest(manifest) when is_map(manifest), do: normalized_jcs_digest(manifest)
  def manifest_digest(_), do: {:error, :invalid_payload}

  defp normalized_payload_map(payload) when is_map(payload) do
    result =
      payload
      |> Attestation.strip_metadata()
      |> normalize()

    case result do
      {:ok, map} when is_map(map) -> {:ok, map}
      {:ok, _} -> {:error, :invalid_payload}
      {:error, reason} -> {:error, reason}
    end
  end

  defp normalized_payload_map(_), do: {:error, :invalid_payload}

  defp normalized_jcs_digest(value) do
    with {:ok, normalized} <- normalize(value),
         {:ok, canonical} <- JCS.encode(normalized) do
      {:ok, sha256_hex(canonical)}
    else
      {:error, :invalid_map} -> {:error, :invalid_payload}
      {:error, reason} -> {:error, reason}
    end
  end

  defp normalize_value(nil), do: {:ok, nil}
  defp normalize_value(value) when is_boolean(value), do: {:ok, value}
  defp normalize_value(value) when is_integer(value), do: {:ok, value}
  defp normalize_value(value) when is_float(value), do: {:ok, value}

  defp normalize_value(value) when is_atom(value) do
    {:ok, Atom.to_string(value)}
  end

  defp normalize_value(value) when is_binary(value) do
    if String.valid?(value), do: {:ok, value}, else: {:error, :invalid_payload}
  end

  defp normalize_value(value) when is_list(value) do
    value
    |> Enum.reduce_while({:ok, []}, fn item, {:ok, items} ->
      case normalize_value(item) do
        {:ok, normalized} -> {:cont, {:ok, [normalized | items]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> reverse_ok()
  end

  defp normalize_value(%_{}), do: {:error, :invalid_payload}

  defp normalize_value(value) when is_map(value) do
    result =
      Enum.reduce_while(value, {:ok, %{}}, fn {key, raw_value}, {:ok, normalized} ->
        with {:ok, key} <- normalize_key(key),
             {:ok, value} <- normalize_value(raw_value),
             :ok <- unique_key(normalized, key) do
          {:cont, {:ok, put_normalized_value(normalized, key, value)}}
        else
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)

    case result do
      {:ok, normalized} -> {:ok, normalized}
      {:error, reason} -> {:error, reason}
    end
  end

  defp normalize_value(_), do: {:error, :invalid_payload}

  defp put_normalized_value(map, _, nil), do: map
  defp put_normalized_value(map, key, value), do: Map.put(map, key, value)

  defp normalize_key(key) when is_atom(key), do: {:ok, Atom.to_string(key)}

  defp normalize_key(key) when is_binary(key) do
    if String.valid?(key), do: {:ok, key}, else: {:error, :invalid_payload}
  end

  defp normalize_key(_), do: {:error, :invalid_payload}

  defp unique_key(map, key) do
    if Map.has_key?(map, key), do: {:error, :invalid_payload}, else: :ok
  end

  defp reverse_ok({:ok, values}), do: {:ok, Enum.reverse(values)}
  defp reverse_ok({:error, reason}), do: {:error, reason}

  defp context_map(context), do: Context.new(context) |> Map.from_struct()

  defp context_extra_or_known(context, key) do
    context_extra(context, key) || Map.get(context_map(context), atom_key(key))
  end

  defp context_extra(context, key) do
    result =
      context
      |> raw_map()
      |> fetch_flexible(key)

    case result do
      {:ok, value} -> value
      :error -> nil
    end
  end

  defp required_context_field(context, key) do
    case context_extra_or_known(context, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      value when is_atom(value) and not is_nil(value) -> {:ok, Atom.to_string(value)}
      _ -> {:error, :invalid_payload}
    end
  end

  defp tool_request_tool(payload, context) do
    case context_extra_or_known(context, "tool") do
      value when is_binary(value) and value != "" ->
        {:ok, value}

      value when is_atom(value) and not is_nil(value) ->
        {:ok, Atom.to_string(value)}

      _ ->
        payload
        |> nested_payload_field(["params", "name"])
        |> fallback_payload_field(payload, "name")
    end
  end

  defp fallback_payload_field({:ok, value}, _, _), do: {:ok, value}
  defp fallback_payload_field(:error, payload, key), do: required_payload_field(payload, key)

  defp tool_request_arguments(payload) do
    case nested_payload_field(payload, ["params", "arguments"]) do
      {:ok, arguments} -> Attestation.strip_metadata(arguments)
      :error -> Map.get(payload, "arguments") |> Attestation.strip_metadata()
    end
  end

  defp nested_payload_field(payload, [parent, child]) do
    case Map.get(payload, parent) do
      parent_value when is_map(parent_value) -> optional_payload_field(parent_value, child)
      _ -> :error
    end
  end

  defp optional_payload_field(payload, key) do
    case Map.get(payload, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      nil -> :error
      value -> {:ok, value}
    end
  end

  defp required_payload_field(payload, key) do
    case Map.get(payload, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      value when is_list(value) -> {:ok, value}
      value when is_map(value) -> {:ok, value}
      value when is_number(value) -> {:ok, value}
      value when is_boolean(value) -> {:ok, value}
      _ -> {:error, :invalid_payload}
    end
  end

  defp repo_paths(payload) do
    case Map.get(payload, "paths") do
      paths when is_list(paths) ->
        if Enum.all?(paths, &is_binary/1) do
          {:ok, Enum.sort(paths)}
        else
          {:error, :invalid_payload}
        end

      _ ->
        {:error, :invalid_payload}
    end
  end

  defp release_artifacts(payload) do
    case Map.get(payload, "artifacts") do
      artifacts when is_list(artifacts) and artifacts != [] ->
        normalize_artifacts(artifacts)

      _ ->
        {:error, :invalid_payload}
    end
  end

  defp normalize_artifacts(artifacts) do
    result =
      Enum.reduce_while(artifacts, {:ok, []}, fn artifact, {:ok, acc} ->
        case normalize_artifact(artifact) do
          {:ok, normalized} -> {:cont, {:ok, [normalized | acc]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)

    case result do
      {:ok, normalized} -> {:ok, Enum.sort_by(normalized, &Map.fetch!(&1, "name"))}
      {:error, reason} -> {:error, reason}
    end
  end

  defp normalize_artifact(%{} = artifact) do
    with {:ok, artifact} <- normalize(artifact),
         {:ok, name} <- required_payload_field(artifact, "name"),
         {:ok, sha256} <- artifact_sha256(artifact) do
      {:ok, %{"name" => name, "sha256" => sha256}}
    end
  end

  defp normalize_artifact(_), do: {:error, :invalid_payload}

  defp artifact_sha256(artifact) do
    case Map.get(artifact, "sha256") do
      value when is_binary(value) ->
        if Regex.match?(@sha256_regex, value), do: {:ok, value}, else: {:error, :invalid_payload}

      _ ->
        {:error, :invalid_payload}
    end
  end

  defp request_action_digest(opts) do
    case Keyword.fetch(opts, :request_action_digest) do
      {:ok, value} when is_binary(value) ->
        if Regex.match?(@sha256_regex, value), do: {:ok, value}, else: {:error, :invalid_payload}

      _ ->
        {:error, :invalid_payload}
    end
  end

  defp maybe_manifest_digest(statement_type, opts)
       when statement_type in [:tool_request, :tool_result, :agent_request, :agent_response] do
    cond do
      Keyword.has_key?(opts, :manifest_digest) ->
        validate_digest(Keyword.fetch!(opts, :manifest_digest))

      Keyword.has_key?(opts, :manifest) ->
        manifest_digest(Keyword.fetch!(opts, :manifest))

      true ->
        {:ok, nil}
    end
  end

  defp maybe_manifest_digest(_, _), do: {:ok, nil}

  defp validate_digest(value) when is_binary(value) do
    if Regex.match?(@sha256_regex, value), do: {:ok, value}, else: {:error, :invalid_payload}
  end

  defp validate_digest(_), do: {:error, :invalid_payload}

  defp raw_map(%Context{} = context), do: Map.from_struct(context)
  defp raw_map(context) when is_list(context), do: Map.new(context)
  defp raw_map(context) when is_map(context), do: context
  defp raw_map(_), do: %{}

  defp fetch_flexible(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} -> {:ok, value}
      :error -> Map.fetch(map, atom_key(key))
    end
  end

  defp maybe_put(map, _, nil), do: map
  defp maybe_put(map, _, {:error, _}), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp ok(value), do: {:ok, value}

  defp sha256_hex(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

  defp atom_key("actor"), do: :actor
  defp atom_key("identity"), do: :identity
  defp atom_key("trust_level"), do: :trust_level
  defp atom_key("phase"), do: :phase
  defp atom_key("origin"), do: :origin
  defp atom_key("source"), do: :source
  defp atom_key("sink"), do: :sink
  defp atom_key("trust_zone"), do: :trust_zone
  defp atom_key("mcp_server"), do: :mcp_server
  defp atom_key("tool"), do: :tool
  defp atom_key("resource_uri"), do: :resource_uri
  defp atom_key("intended_audience"), do: :intended_audience
  defp atom_key("sandbox_id"), do: :sandbox_id
  defp atom_key("isolation_level"), do: :isolation_level
  defp atom_key(_), do: :__unknown__
end
