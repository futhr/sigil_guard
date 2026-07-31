defmodule SigilGuard.MCP.SecurityPayload do
  @moduledoc """
  Builds the structured MCP value bound by policy, confirmations, and attestations.

  Security decisions must distinguish structurally different calls. This
  module therefore keeps map keys, arrays, numbers, booleans, `nil`,
  `inputResponses`, `inputRequests`, and opaque `requestState` values. It does
  not flatten an action into text before computing its digest.

  The projection excludes only fields that cannot change the authorized
  operation:

    * JSON-RPC correlation and encoding fields;
    * SigilGuard's fixed attestation and confirmation metadata;
    * MCP progress, display, logging, subscription-correlation, and trace
      metadata.

  The selected protocol revision is extracted and bound separately. Client
  capabilities and unknown extension metadata remain in the payload because
  they can change request behavior.

  `for_gate/3` returns two views of the same action. `:binding` is the exact
  structured value used by confirmation and attestation digests. `:text` is
  only a scanner projection made from string values; it never becomes the
  authority-bearing representation.

  ## Example

      iex> request = %{
      ...>   "method" => "tools/call",
      ...>   "params" => %{
      ...>     "name" => "payments/create",
      ...>     "arguments" => %{"amount" => 1250, "approved" => false}
      ...>   }
      ...> }
      ...>
      ...> projection = SigilGuard.MCP.SecurityPayload.request(request)
      ...> projection["payload"]["arguments"]
      %{"amount" => 1250, "approved" => false}
  """
  @moduledoc since: "1.0.0"

  alias SigilGuard.MCP.Protocol

  @guard_metadata_keys [
    :_agent_trust,
    "_agent_trust",
    :_agent_confirmation,
    "_agent_confirmation",
    :confirmation_token,
    "confirmation_token"
  ]
  @envelope_keys [
    :jsonrpc,
    "jsonrpc",
    :id,
    "id",
    :request_id,
    "request_id",
    :method,
    "method"
  ]
  @non_semantic_meta_keys [
    :progressToken,
    "progressToken",
    :"io.modelcontextprotocol/protocolVersion",
    "io.modelcontextprotocol/protocolVersion",
    :"io.modelcontextprotocol/clientInfo",
    "io.modelcontextprotocol/clientInfo",
    :"io.modelcontextprotocol/logLevel",
    "io.modelcontextprotocol/logLevel",
    :"io.modelcontextprotocol/serverInfo",
    "io.modelcontextprotocol/serverInfo",
    :"io.modelcontextprotocol/subscriptionId",
    "io.modelcontextprotocol/subscriptionId",
    :traceparent,
    "traceparent",
    :tracestate,
    "tracestate",
    :baggage,
    "baggage"
  ]
  @invalid_payload_field :invalid

  @typedoc "The side of the tool boundary being projected."
  @type direction :: :request | :result

  @typedoc """
  Structured value used for confirmation and attestation binding.

  The `payload` member is the original JSON value after the documented,
  non-semantic metadata exclusions.
  """
  @type projection :: %{required(String.t()) => term()}

  @typedoc "Runtime-gate input carrying scanner text and the exact structured binding."
  @type gate_payload :: %{
          tool: String.t() | nil,
          action: String.t() | nil | :invalid,
          text: String.t(),
          binding: projection()
        }

  @typedoc "A name extracted from an MCP-shaped map, or `:invalid` when present but malformed."
  @type extracted_name :: String.t() | nil | :invalid

  @doc """
  Builds the security projection for an MCP request.

  Pass the original request map. Pre-flattened input loses structural
  distinctions and should not be used for confirmation or attestation.
  """
  @doc since: "1.0.0"
  @spec request(term(), keyword()) :: projection()
  def request(message, opts \\ []), do: projection(message, :request, opts)

  @doc """
  Builds the security projection for an MCP result.

  JSON-RPC response wrappers are unwrapped, while the complete result value is
  retained.
  """
  @doc since: "1.0.0"
  @spec result(term(), keyword()) :: projection()
  def result(message, opts \\ []), do: projection(message, :result, opts)

  @doc """
  Build the runtime-gate payload for an MCP request or result.

  `:text` is a scanner projection only. `:binding` is the canonical structured
  value used by confirmation and attestation digests.
  """
  @doc since: "1.0.0"
  @spec for_gate(term(), direction(), keyword()) :: gate_payload()
  def for_gate(message, direction, opts \\ []) when direction in [:request, :result] do
    binding = projection(message, direction, opts)
    tool = tool_name(message)
    action = action_name(message)

    %{
      tool: context_field(tool),
      action: action_field(action, tool),
      text: scan_text(binding),
      binding: binding
    }
  end

  @doc """
  Extracts the first tool name from common MCP and adapter map shapes.

  Returns `nil` when no candidate field exists and `:invalid` when a candidate
  is present but is not a string. A malformed earlier candidate is never
  hidden by a valid later alias.
  """
  @doc since: "1.0.0"
  @spec tool_name(term()) :: extracted_name()
  def tool_name(payload) do
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

  @doc """
  Extracts the action name used by the runtime policy.

  Tool and adapter aliases are checked before the JSON-RPC method. Returns
  `:invalid` for a present non-string field.
  """
  @doc since: "1.0.0"
  @spec action_name(term()) :: extracted_name()
  def action_name(payload) do
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

  @doc """
  Removes SigilGuard's fixed guard metadata at the root and `params` levels.

  Other metadata is preserved for `request/2` and `result/2` to classify
  according to its MCP semantics.
  """
  @doc since: "1.0.0"
  @spec strip_guard_metadata(term()) :: term()
  def strip_guard_metadata(value) when is_map(value) do
    value
    |> Map.drop(@guard_metadata_keys)
    |> strip_params_metadata(:params)
    |> strip_params_metadata("params")
  end

  def strip_guard_metadata(value), do: value

  defp projection(message, direction, opts) do
    stripped = strip_guard_metadata(message)

    %{
      "kind" => Atom.to_string(direction),
      "method" => method(stripped, direction),
      "protocol_version" => Protocol.version(message, opts),
      "payload" => semantic_payload(stripped, direction)
    }
  end

  defp semantic_payload(message, :request) when is_map(message) do
    case fetch_params(message) do
      {:ok, params} when is_map(params) ->
        strip_non_semantic_meta(params)

      {:ok, params} ->
        params

      :error ->
        message
        |> Map.drop(@envelope_keys)
        |> strip_non_semantic_meta()
    end
  end

  defp semantic_payload(%{"result" => result}, :result),
    do: strip_non_semantic_meta(result)

  defp semantic_payload(%{result: result}, :result),
    do: strip_non_semantic_meta(result)

  defp semantic_payload(message, _), do: strip_non_semantic_meta(message)

  defp method(message, :request) when is_map(message) do
    case Map.get(message, "method", Map.get(message, :method)) do
      value when is_binary(value) -> value
      _ -> action_name(message)
    end
  end

  defp method(_, :request), do: nil
  defp method(_, :result), do: nil

  defp fetch_params(message) do
    cond do
      Map.has_key?(message, "params") -> {:ok, Map.fetch!(message, "params")}
      Map.has_key?(message, :params) -> {:ok, Map.fetch!(message, :params)}
      true -> :error
    end
  end

  defp strip_params_metadata(payload, params_key) do
    case Map.get(payload, params_key) do
      params when is_map(params) ->
        Map.put(payload, params_key, Map.drop(params, @guard_metadata_keys))

      _ ->
        payload
    end
  end

  defp strip_non_semantic_meta(payload) when is_map(payload) do
    payload
    |> strip_meta_key(:_meta)
    |> strip_meta_key("_meta")
  end

  defp strip_non_semantic_meta(payload), do: payload

  defp strip_meta_key(payload, key) do
    case Map.fetch(payload, key) do
      {:ok, metadata} when is_map(metadata) ->
        semantic_metadata = Map.drop(metadata, @non_semantic_meta_keys)

        if map_size(semantic_metadata) == 0 do
          Map.delete(payload, key)
        else
          Map.put(payload, key, semantic_metadata)
        end

      _ ->
        payload
    end
  end

  defp scan_text(payload) do
    payload
    |> collect_strings([])
    |> Enum.reverse()
    |> Enum.join("\n")
  end

  defp collect_strings(value, acc) when is_binary(value), do: [value | acc]

  defp collect_strings(value, acc) when is_list(value),
    do: Enum.reduce(value, acc, &collect_strings/2)

  defp collect_strings(value, acc) when is_map(value) do
    value
    |> Map.values()
    |> Enum.reduce(acc, &collect_strings/2)
  end

  defp collect_strings(_, acc), do: acc

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
end
