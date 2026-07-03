defmodule SigilGuard.TransportExamples do
  @moduledoc """
  Transport-neutral `ToolGateway` context examples.

  HTTP MCP uses the canonical server URI as both the MCP server identifier and
  the resource indicator:

      iex> request =
      ...>   SigilGuard.TransportExamples.tool_call("repo_file_write", %{
      ...>     "path" => "README.md",
      ...>     "content" => "ok"
      ...>   })
      ...>
      ...> context =
      ...>   SigilGuard.TransportExamples.http_mcp_context(
      ...>     "https://mcp.example.com/mcp",
      ...>     "repo_file_write"
      ...>   )
      ...>
      ...> {:ok, decision} =
      ...>   SigilGuard.ToolGateway.guarded_request(request, context, require_manifest: false)
      ...>
      ...> decision.audit_metadata.mcp_server
      "https://mcp.example.com/mcp"

  Stdio MCP uses a host-assigned local runner id in the same `mcp_server`
  field:

      iex> context =
      ...>   SigilGuard.TransportExamples.stdio_mcp_context("stdio:repo-tools", "repo_file_write")
      ...>
      ...> context.mcp_server
      "stdio:repo-tools"

  In-process tools also use a host-assigned local runner id, so the same
  manifest `server` rule applies without a network transport:

      iex> context =
      ...>   SigilGuard.TransportExamples.in_process_context(
      ...>     "local:release-runner",
      ...>     "repo_file_write"
      ...>   )
      ...>
      ...> context.resource_uri
      "mcp://local/local:release-runner"
  """

  alias SigilGuard.Context

  @type tool_call_request :: %{
          required(String.t()) =>
            String.t()
            | %{
                required(String.t()) => String.t() | map()
              }
        }

  @doc """
  Build a minimal MCP `tools/call` request map for examples.
  """
  @spec tool_call(String.t(), map()) :: tool_call_request()
  def tool_call(name, arguments) when is_binary(name) and is_map(arguments) do
    %{
      "jsonrpc" => "2.0",
      "id" => "example",
      "method" => "tools/call",
      "params" => %{"name" => name, "arguments" => arguments}
    }
  end

  @doc """
  Build an HTTP MCP boundary context from a canonical server URI.
  """
  @spec http_mcp_context(String.t(), String.t()) :: Context.t()
  def http_mcp_context(server_uri, tool)
      when is_binary(server_uri) and is_binary(tool) do
    base_context(server_uri, server_uri, tool)
  end

  @doc """
  Build a stdio MCP boundary context from a host-assigned local runner id.
  """
  @spec stdio_mcp_context(String.t(), String.t()) :: Context.t()
  def stdio_mcp_context(runner_id, tool)
      when is_binary(runner_id) and is_binary(tool) do
    base_context(runner_id, "mcp://local/" <> runner_id, tool)
  end

  @doc """
  Build an in-process tool boundary context from a host-assigned local runner id.
  """
  @spec in_process_context(String.t(), String.t()) :: Context.t()
  def in_process_context(runner_id, tool)
      when is_binary(runner_id) and is_binary(tool) do
    base_context(runner_id, "mcp://local/" <> runner_id, tool)
  end

  defp base_context(server, resource_uri, tool) do
    Context.new(
      phase: :tool_request,
      origin: :model,
      sink: :tool,
      mcp_server: server,
      resource_uri: resource_uri,
      tool: tool,
      action: tool,
      trust_level: :high,
      metadata: %{sandbox_id: "example-sandbox", isolation_level: "container"}
    )
  end
end
