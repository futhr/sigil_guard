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
  @blocked_code -32_001
  @confirm_code -32_002
  @quarantine_code -32_003

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
  Guard an MCP tool request and return either an allow decision or JSON-RPC error.

  This helper is intended for gateway adapters that need a wire-shaped response
  rather than only a `%SigilGuard.Decision{}`.
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
  Guard an MCP tool result before model ingestion.
  """
  @spec guard_result(term(), Context.t() | map() | keyword(), keyword()) :: Decision.t()
  def guard_result(result, context \\ %{}, opts \\ []) do
    result
    |> gate_payload()
    |> Runtime.Gate.evaluate(result_context(result, context), opts)
  end

  @doc """
  Guard an MCP tool result and return a safe MCP-shaped result or JSON-RPC error.

  Redacted results are returned as JSON-RPC result objects containing sanitized
  text. Blocked, quarantined, or confirmation-required results become JSON-RPC
  errors with audit-safe metadata only.
  """
  @spec guarded_result(term(), Context.t() | map() | keyword(), keyword()) ::
          {:ok, map(), Decision.t()} | {:error, map(), Decision.t()}
  def guarded_result(result, context \\ %{}, opts \\ []) do
    decision = guard_result(result, context, opts)

    case decision.action do
      :allow ->
        {:ok, jsonrpc_result(result, request_id(result)), decision}

      :redact ->
        {:ok, sanitized_result(result, decision, request_id(result)), decision}

      _ ->
        {:error, response_for_decision(decision, request_id(result), opts), decision}
    end
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

  @doc """
  Convert a runtime decision into an audit-safe JSON-RPC response.

  The response intentionally omits raw payload text. Metadata includes hashes,
  counts, indicator identifiers, and confirmation digests when available.
  """
  @spec response_for_decision(Decision.t(), term(), keyword()) :: map()
  def response_for_decision(%Decision{} = decision, id \\ nil, opts \\ []) do
    if decision.verdict == :allowed and decision.action in [:allow, :redact] do
      sanitized_result(%{}, decision, id)
    else
      jsonrpc_error(id, error_code(decision), error_message(decision), error_data(decision, opts))
    end
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
    Enum.find_value(paths, &string_at(payload, &1))
  end

  defp first_payload_value(_, _), do: nil

  defp string_at(payload, path) do
    case get_in(payload, path) do
      value when is_binary(value) -> value
      _ -> nil
    end
  end

  defp executable?(%Decision{verdict: :allowed, action: action}), do: action in [:allow, :redact]
  defp executable?(%Decision{}), do: false

  defp request_id(payload) when is_map(payload) do
    first_payload_term(payload, [
      [:id],
      ["id"],
      [:request_id],
      ["request_id"]
    ])
  end

  defp request_id(_), do: nil

  defp first_payload_term(payload, paths) when is_map(payload) do
    Enum.find_value(paths, &get_in(payload, &1))
  end

  defp jsonrpc_result(%{"jsonrpc" => _, "id" => id, "result" => result}, _) do
    %{"jsonrpc" => "2.0", "id" => id, "result" => result}
  end

  defp jsonrpc_result(%{jsonrpc: _, id: id, result: result}, _) do
    %{"jsonrpc" => "2.0", "id" => id, "result" => result}
  end

  defp jsonrpc_result(result, id) do
    %{"jsonrpc" => "2.0", "id" => id, "result" => result}
  end

  defp sanitized_result(result, %Decision{} = decision, id) do
    result
    |> jsonrpc_result(id)
    |> put_in(["result"], sanitized_payload(decision))
  end

  defp sanitized_payload(%Decision{sanitized_text: text}) when is_binary(text) do
    %{
      "content" => [
        %{"type" => "text", "text" => text}
      ]
    }
  end

  defp sanitized_payload(%Decision{}), do: %{"content" => []}

  defp jsonrpc_error(id, code, message, data) do
    %{
      "jsonrpc" => "2.0",
      "id" => id,
      "error" => %{
        "code" => code,
        "message" => message,
        "data" => data
      }
    }
  end

  defp error_code(%Decision{action: :quarantine}), do: @quarantine_code
  defp error_code(%Decision{verdict: {:confirm, _}}), do: @confirm_code
  defp error_code(%Decision{}), do: @blocked_code

  defp error_message(%Decision{action: :quarantine}), do: "SigilGuard quarantined MCP content"
  defp error_message(%Decision{verdict: {:confirm, _}}), do: "SigilGuard requires confirmation"
  defp error_message(%Decision{}), do: "SigilGuard blocked MCP content"

  defp error_data(%Decision{} = decision, opts) do
    base = %{
      "status" => error_status(decision),
      "action" => Atom.to_string(decision.action),
      "reason" => decision.reason,
      "phase" => Atom.to_string(decision.phase),
      "risk_level" => Atom.to_string(decision.risk_level),
      "trust_level" => Atom.to_string(decision.trust_level),
      "hit_count" => length(decision.hits),
      "indicator_ids" => Enum.map(decision.indicators, &Atom.to_string(&1.id)),
      "content_hash" => decision.content_hash,
      "action_digest" => decision.audit_metadata[:action_digest]
    }

    if Keyword.get(opts, :include_sanitized, false) and is_binary(decision.sanitized_text) do
      Map.put(base, "sanitized_text", decision.sanitized_text)
    else
      base
    end
  end

  defp error_status(%Decision{action: :quarantine}), do: "quarantined"
  defp error_status(%Decision{verdict: {:confirm, _}}), do: "confirmation_required"
  defp error_status(%Decision{}), do: "blocked"
end
