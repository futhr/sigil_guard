defmodule SigilGuard.MCP.Gateway do
  @moduledoc """
  Transport-agnostic MCP guard helpers.

  The module accepts MCP-shaped maps, normalizes common request/result fields,
  labels the relevant trust boundary, and delegates enforcement to
  `SigilGuard.Runtime.Gate`. It does not depend on a particular MCP server
  or client package.
  """

  alias SigilGuard.Context
  alias SigilGuard.Decision
  alias SigilGuard.Runtime

  @known_context_keys Map.keys(%Context{})

  @doc """
  Guard an MCP tool request before execution.

  Common JSON-RPC MCP tool-call shapes are supported, including
  `%{"method" => "tools/call", "params" => %{"name" => tool, "arguments" => args}}`.
  """
  @spec guard_request(term(), Context.t() | map() | keyword(), keyword()) :: Decision.t()
  def guard_request(request, context \\ %{}, opts \\ []) do
    request
    |> gate_payload()
    |> Runtime.Gate.evaluate(request_context(request, context), opts)
  end

  @doc """
  Guard an MCP tool result before model ingestion.
  """
  @spec guard_result(term(), Context.t() | map() | keyword(), keyword()) :: Decision.t()
  def guard_result(result, context \\ %{}, opts \\ []) do
    result
    |> gate_payload()
    |> Runtime.Gate.evaluate(result_context(result, context), opts)
  end

  @doc """
  Start a chunk-safe stream sanitizer for MCP tool results.
  """
  @spec stream_result(Context.t() | map() | keyword(), keyword()) :: Runtime.Stream.t()
  def stream_result(context \\ %{}, opts \\ []) do
    %{}
    |> result_context(context)
    |> Runtime.Stream.new(opts)
  end

  defp request_context(request, context) do
    defaults = %{
      phase: :tool_request,
      origin: :model,
      sink: :tool,
      tool: tool_name(request),
      action: action_name(request),
      mcp_server: mcp_server(request)
    }

    merge_context(defaults, context)
  end

  defp result_context(result, context) do
    defaults = %{
      phase: :tool_result,
      origin: :tool,
      sink: :model,
      tool: tool_name(result),
      action: action_name(result),
      mcp_server: mcp_server(result)
    }

    merge_context(defaults, context)
  end

  defp merge_context(defaults, context) do
    context
    |> context_overrides()
    |> then(&Map.merge(defaults, &1))
    |> Context.new()
  end

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

  defp gate_payload(payload) do
    %{
      tool: tool_name(payload),
      action: action_name(payload),
      text: text_payload(payload)
    }
  end

  defp text_payload(payload) do
    case Context.text(payload) do
      text when is_binary(text) -> text
      _ -> joined_strings(payload)
    end
  end

  defp joined_strings(payload) do
    payload
    |> collect_strings()
    |> Enum.reverse()
    |> Enum.join("\n")
  end

  defp collect_strings(value), do: collect_strings(value, [])

  defp collect_strings(value, acc) when is_binary(value), do: [value | acc]

  defp collect_strings(value, acc) when is_list(value) do
    Enum.reduce(value, acc, &collect_strings/2)
  end

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
      [:method],
      ["method"],
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
    Enum.find_value(paths, &string_at(payload, &1))
  end

  defp first_payload_value(_, _), do: nil

  defp string_at(payload, path) do
    case get_in(payload, path) do
      value when is_binary(value) -> value
      _ -> nil
    end
  end
end
