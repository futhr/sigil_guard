defmodule SigilGuard.MCP.Protocol do
  @moduledoc """
  Selects MCP protocol semantics and reads result discriminators.

  SigilGuard is deliberately transport-neutral. It neither calls
  `server/discover` nor negotiates protocol revisions; the host adapter does
  that work and passes the selected revision to this module. When no explicit
  revision is supplied, `version/2` reads
  `io.modelcontextprotocol/protocolVersion` from request `_meta`.

  The host must validate the complete per-request metadata before invoking
  application code. MCP v2 requires both the protocol revision and client
  capabilities on every request. Missing fields use JSON-RPC `-32602`,
  unsupported revisions use `-32022`, and required but undeclared capabilities
  use `-32021`; SigilGuard does not emit those protocol errors.

  Only `2026-07-28` is treated as the modern revision. An unknown future date
  is not assumed to be compatible: the adapter must first establish support
  and SigilGuard must deliberately add that revision.

  Result helpers understand the final protocol's `resultType` discriminator
  and its `"input_required"` multi-round-trip result. They preserve any
  discriminator already present, including malformed or extension values, so
  a protocol validator can reject it instead of SigilGuard silently rewriting
  the wire value.

  ## Example

      iex> request = %{
      ...>   "params" => %{
      ...>     "_meta" => %{
      ...>       "io.modelcontextprotocol/protocolVersion" => "2026-07-28",
      ...>       "io.modelcontextprotocol/clientCapabilities" => %{}
      ...>     }
      ...>   }
      ...> }
      ...>
      ...> SigilGuard.MCP.Protocol.version(request)
      "2026-07-28"
      iex> SigilGuard.MCP.Protocol.ensure_result_type(%{"content" => []}, request)
      %{"content" => [], "resultType" => "complete"}
  """
  @moduledoc since: "1.0.0"

  @current_version "2026-07-28"
  @protocol_version_key "io.modelcontextprotocol/protocolVersion"

  @typedoc "A date-versioned MCP protocol revision such as `\"2026-07-28\"`."
  @type version :: String.t()

  @doc "Returns the MCP revision implemented by the modern response helpers."
  @doc since: "1.0.0"
  @spec current_version() :: version()
  def current_version, do: @current_version

  @doc """
  Returns the protocol revision selected for `message`.

  A non-empty `:protocol_version` option takes precedence. Otherwise the
  function reads the standard MCP key from `params._meta`, with root `_meta`
  accepted for direct adapter maps. Missing or malformed values return `nil`.
  """
  @doc since: "1.0.0"
  @spec version(term(), keyword()) :: version() | nil
  def version(message, opts \\ [])

  def version(message, opts) when is_list(opts) do
    case Keyword.get(opts, :protocol_version) do
      value when is_binary(value) and value != "" -> value
      _ -> message_version(message)
    end
  end

  def version(message, _), do: message_version(message)

  @doc """
  Returns whether `message` explicitly selects MCP `2026-07-28`.

  Earlier, malformed, and unknown future revisions return `false`.
  """
  @doc since: "1.0.0"
  @spec modern?(term(), keyword()) :: boolean()
  def modern?(message, opts \\ []) do
    case version(message, opts) do
      value when is_binary(value) -> modern_version?(value)
      _ -> false
    end
  end

  @doc """
  Returns a valid string `resultType` from a response or direct result map.

  Atom-keyed and snake-case adapter maps are accepted in addition to the MCP
  wire key. Missing or non-string values return `nil`.
  """
  @doc since: "1.0.0"
  @spec result_type(term()) :: String.t() | nil
  def result_type(%{"result" => result}) when is_map(result), do: result_type(result)
  def result_type(%{result: result}) when is_map(result), do: result_type(result)
  def result_type(%{"resultType" => value}) when is_binary(value), do: value
  def result_type(%{resultType: value}) when is_binary(value), do: value
  def result_type(%{"result_type" => value}) when is_binary(value), do: value
  def result_type(%{result_type: value}) when is_binary(value), do: value
  def result_type(_), do: nil

  @doc "Returns whether a result requests another MCP round trip."
  @doc since: "1.0.0"
  @spec input_required?(term()) :: boolean()
  def input_required?(message), do: result_type(message) == "input_required"

  @doc """
  Add `resultType: "complete"` to a direct result map for modern MCP.

  Existing discriminators are never overwritten. This includes
  `"input_required"`, extension values, and malformed values that a host
  protocol validator still needs to reject. Earlier revisions retain their
  original map shape.
  """
  @doc since: "1.0.0"
  @spec ensure_result_type(term(), term(), keyword()) :: term()
  def ensure_result_type(result, version_source, opts \\ [])

  def ensure_result_type(result, version_source, opts) when is_map(result) and is_list(opts) do
    if modern?(version_source, opts) and not has_result_type?(result) do
      Map.put(result, "resultType", "complete")
    else
      result
    end
  end

  def ensure_result_type(result, _, _), do: result

  defp message_version(message) when is_map(message) do
    first_value(message, [
      [:params, :_meta, @protocol_version_key],
      [:params, "_meta", @protocol_version_key],
      ["params", :_meta, @protocol_version_key],
      ["params", "_meta", @protocol_version_key],
      [:_meta, @protocol_version_key],
      ["_meta", @protocol_version_key]
    ])
  end

  defp message_version(_), do: nil

  defp first_value(map, paths) do
    Enum.find_value(paths, fn path ->
      case fetch_path(map, path) do
        {:ok, value} when is_binary(value) and value != "" -> value
        _ -> nil
      end
    end)
  end

  defp fetch_path(value, []), do: {:ok, value}

  defp fetch_path(value, [key | rest]) when is_map(value) do
    case Map.fetch(value, key) do
      {:ok, next} -> fetch_path(next, rest)
      :error -> :error
    end
  end

  defp fetch_path(_, _), do: :error

  defp modern_version?(@current_version), do: true
  defp modern_version?(_), do: false

  defp has_result_type?(result) do
    Enum.any?(
      ["resultType", :resultType, "result_type", :result_type],
      &Map.has_key?(result, &1)
    )
  end
end
