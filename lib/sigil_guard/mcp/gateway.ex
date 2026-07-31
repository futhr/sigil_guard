defmodule SigilGuard.MCP.Gateway do
  @moduledoc """
  Guards MCP requests and results at a host-owned transport boundary.

  This module is the stable adapter facade for MCP clients, servers, and
  gateways. It accepts decoded MCP-shaped values and returns decisions or
  JSON-RPC-compatible tuple shapes while delegating policy enforcement to
  `SigilGuard.ToolGateway`.

  SigilGuard does not negotiate the protocol, perform discovery, own
  authorization, or send transport messages. The host supplies the negotiated
  protocol revision through the request's standard `_meta` or the
  `:protocol_version` option. For MCP v2 (`2026-07-28`), the host is also
  responsible for validating the complete wire request, including required
  client capabilities.

  Calls without “confirmed” in their name deliberately disable confirmation
  handling. Confirmed variants honor an action-bound token. Use
  `SigilGuard.ToolGateway` directly when the host also needs manifest
  verification, attestation creation, or the complete policy option surface.

  ## Return values

  Decision-only functions return a `SigilGuard.Decision` struct. Guarded
  request functions return `{:ok, decision}` when execution may continue or
  `{:error, response, decision}` when the adapter must reject the call.
  Guarded result functions also return the safe MCP result that may cross back
  to the model.

  ## Examples

      request = %{
        "id" => "call-1",
        "method" => "tools/call",
        "params" => %{
          "name" => "read_file",
          "arguments" => %{"path" => "README.md"},
          "_meta" => %{
            "io.modelcontextprotocol/protocolVersion" => "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities" => %{}
          }
        }
      }

      context = [phase: :tool_request, origin: :model, sink: :tool]

      case SigilGuard.MCP.Gateway.guarded_request(request, context) do
        {:ok, decision} -> {:execute, decision}
        {:error, response, decision} -> {:reject, response, decision}
      end
  """
  @moduledoc since: "1.0.0"

  alias SigilGuard.Context
  alias SigilGuard.Decision
  alias SigilGuard.ToolGateway
  alias SigilGuard.ToolGateway.Base

  @typedoc "Boundary context accepted by all gateway helpers."
  @type ctx :: Context.t() | map() | keyword()

  @doc """
  Guard an MCP tool request before execution.
  """
  @spec guard_request(term(), ctx(), keyword()) :: Decision.t()
  def guard_request(request, context \\ %{}, opts \\ []) do
    ToolGateway.guard_request(request, context, force_opts(opts, confirmation: :off))
  end

  @doc """
  Guard an MCP tool request and return either an allow decision or JSON-RPC error.
  """
  @spec guarded_request(term(), ctx(), keyword()) ::
          {:ok, Decision.t()} | {:error, map(), Decision.t()}
  def guarded_request(request, context \\ %{}, opts \\ []) do
    ToolGateway.guarded_request(request, context, force_opts(opts, confirmation: :off))
  end

  @doc """
  Issue an action-bound confirmation token for a confirm-required MCP request.
  """
  @spec issue_confirmation_token(term(), ctx(), Decision.t(), binary(), keyword()) ::
          {:ok, String.t()} | {:error, ToolGateway.confirmation_issue_error()}
  def issue_confirmation_token(request, context, %Decision{} = decision, key, opts \\ []) do
    ToolGateway.issue_confirmation(
      request,
      context,
      decision,
      key,
      force_opts(opts, direction: :request)
    )
  end

  @doc """
  Fail closed for signed MCP requests that lack valid Agent Trust evidence.
  """
  @spec issue_signed_confirmation_token(term(), ctx(), Decision.t(), binary(), keyword()) ::
          {:ok, String.t()} | {:error, term()}
  def issue_signed_confirmation_token(request, context, %Decision{} = decision, key, opts \\ []) do
    Base.issue_signed_confirmation_token(request, context, decision, key, opts)
  end

  @doc """
  Issue an action-bound confirmation token for a confirm-required MCP result.
  """
  @spec issue_result_confirmation_token(term(), ctx(), Decision.t(), binary(), keyword()) ::
          {:ok, String.t()} | {:error, ToolGateway.confirmation_issue_error()}
  def issue_result_confirmation_token(result, context, %Decision{} = decision, key, opts \\ []) do
    ToolGateway.issue_confirmation(
      result,
      context,
      decision,
      key,
      force_opts(opts, direction: :result)
    )
  end

  @doc """
  Guard an MCP tool request and honor an optional confirmation token.
  """
  @spec guard_confirmed_request(term(), ctx(), keyword()) :: Decision.t()
  def guard_confirmed_request(request, context \\ %{}, opts \\ []) do
    ToolGateway.guard_request(request, context, opts)
  end

  @doc """
  Guard a possibly confirmed MCP request and return either an allow decision or JSON-RPC error.
  """
  @spec guarded_confirmed_request(term(), ctx(), keyword()) ::
          {:ok, Decision.t()} | {:error, map(), Decision.t()}
  def guarded_confirmed_request(request, context \\ %{}, opts \\ []) do
    ToolGateway.guarded_request(request, context, opts)
  end

  @doc """
  Fail closed for legacy signed MCP requests and optional confirmation tokens.
  """
  @spec guard_signed_confirmed_request(term(), ctx(), keyword()) :: Decision.t()
  def guard_signed_confirmed_request(request, context \\ %{}, opts \\ []) do
    Base.guard_signed_confirmed_request(request, context, opts)
  end

  @doc """
  Fail closed for legacy signed, possibly confirmed MCP requests and return a JSON-RPC error.
  """
  @spec guarded_signed_confirmed_request(term(), ctx(), keyword()) ::
          {:ok, Decision.t()} | {:error, map(), Decision.t()}
  def guarded_signed_confirmed_request(request, context \\ %{}, opts \\ []) do
    Base.guarded_signed_confirmed_request(request, context, opts)
  end

  @doc """
  Fail closed for legacy signed MCP tool requests before execution.
  """
  @spec guard_signed_request(term(), ctx(), keyword()) :: Decision.t()
  def guard_signed_request(request, context \\ %{}, opts \\ []) do
    Base.guard_signed_request(request, context, opts)
  end

  @doc """
  Fail closed for legacy signed MCP tool requests and return a JSON-RPC error.
  """
  @spec guarded_signed_request(term(), ctx(), keyword()) ::
          {:ok, Decision.t()} | {:error, map(), Decision.t()}
  def guarded_signed_request(request, context \\ %{}, opts \\ []) do
    Base.guarded_signed_request(request, context, opts)
  end

  @doc """
  Reject legacy signed MCP request metadata without running the runtime gate.
  """
  @spec verify_request_envelope(term(), keyword()) ::
          {:ok, %{identity: String.t(), envelope: map()}} | {:error, atom()}
  def verify_request_envelope(request, opts \\ []) do
    Base.verify_request_envelope(request, opts)
  end

  @doc """
  Guard an MCP tool result before model ingestion.
  """
  @spec guard_result(term(), ctx(), keyword()) :: Decision.t()
  def guard_result(result, context \\ %{}, opts \\ []) do
    ToolGateway.guard_result(result, context, force_opts(opts, confirmation: :off))
  end

  @doc """
  Guard an MCP tool result and honor an optional confirmation token.
  """
  @spec guard_confirmed_result(term(), ctx(), keyword()) :: Decision.t()
  def guard_confirmed_result(result, context \\ %{}, opts \\ []) do
    ToolGateway.guard_result(result, context, opts)
  end

  @doc """
  Guard an MCP tool result and return a safe MCP-shaped result or JSON-RPC error.
  """
  @spec guarded_result(term(), ctx(), keyword()) ::
          {:ok, map(), Decision.t()} | {:error, map(), Decision.t()}
  def guarded_result(result, context \\ %{}, opts \\ []) do
    ToolGateway.guarded_result(result, context, force_opts(opts, confirmation: :off))
  end

  @doc """
  Guard a possibly confirmed MCP result and return a safe MCP-shaped result or JSON-RPC error.
  """
  @spec guarded_confirmed_result(term(), ctx(), keyword()) ::
          {:ok, map(), Decision.t()} | {:error, map(), Decision.t()}
  def guarded_confirmed_result(result, context \\ %{}, opts \\ []) do
    ToolGateway.guarded_result(result, context, opts)
  end

  @doc """
  Start a chunk-safe stream sanitizer for MCP tool results.
  """
  @spec stream_result(ctx(), keyword()) :: SigilGuard.Runtime.Stream.t()
  def stream_result(context \\ %{}, opts \\ []) do
    ToolGateway.stream_result(context, opts)
  end

  @doc """
  Push one MCP tool-result stream chunk through the gateway sanitizer.
  """
  @spec guarded_result_chunk(SigilGuard.Runtime.Stream.t(), String.t(), keyword()) ::
          {SigilGuard.Runtime.Stream.t(),
           {:ok, map() | nil, Decision.t()} | {:error, map(), Decision.t()}}
  def guarded_result_chunk(stream, chunk, opts \\ []) do
    ToolGateway.guarded_result_chunk(stream, chunk, opts)
  end

  @doc """
  Flush a guarded MCP tool-result stream.
  """
  @spec finish_guarded_result_stream(SigilGuard.Runtime.Stream.t(), keyword()) ::
          {SigilGuard.Runtime.Stream.t(),
           {:ok, map() | nil, Decision.t()} | {:error, map(), Decision.t()}}
  def finish_guarded_result_stream(stream, opts \\ []) do
    ToolGateway.finish_guarded_result_stream(stream, opts)
  end

  @doc """
  Convert a runtime decision into an audit-safe JSON-RPC response.
  """
  @spec response_for_decision(Decision.t(), term(), keyword()) :: map()
  def response_for_decision(%Decision{} = decision, id \\ nil, opts \\ []) do
    ToolGateway.response_for_decision(decision, id, opts)
  end

  defp force_opts(opts, replacements) do
    Enum.reduce(replacements, opts, fn {key, value}, acc ->
      Keyword.put(acc, key, value)
    end)
  end
end
