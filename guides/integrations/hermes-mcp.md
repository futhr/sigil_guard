# Hermes MCP Integration

Validation record:

- Target package: `hermes_mcp` `0.14.1`.
- Variant package: `anubis_mcp` `1.6.2`.
- Package metadata checked: 2026-07-07.
- Compile validation: passed on 2026-07-07 with Elixir 1.19.4 / Erlang/OTP 28.
  Scratch projects compiled the SigilGuard interceptor seam, Hermes component
  registration, Plug placement, and Anubis component variant with
  `mix compile --warnings-as-errors`.

Hermes MCP exposes MCP servers through supervised server modules and
Streamable HTTP Plug/Phoenix routing. SigilGuard should sit at the host-owned
boundary immediately before tool execution and immediately before a tool result
returns to the model. It does not replace Hermes transport supervision or MCP
protocol handling.

## Dependencies

For local validation, pin the target and use the SigilGuard checkout as a path
dependency:

```elixir
def deps do
  [
    {:hermes_mcp, "~> 0.14.1"},
    {:plug, "~> 1.18"},
    {:sigil_guard, path: "../sigil_guard", override: true}
  ]
end
```

For the Anubis compile variant:

```elixir
def deps do
  [
    {:anubis_mcp, "~> 1.6.2"},
    {:sigil_guard, path: "../sigil_guard", override: true}
  ]
end
```

## Interceptor Placement

Use an interceptor-style module at the host seam that receives the MCP tool
name, arguments, actor, and execution function. In Hermes, wire this from the
tool callback or the nearest equivalent pre/post hook in the host application.

```elixir
defmodule MyApp.MCP.SigilGuardInterceptor do
  alias SigilGuard.{Decision, ToolGateway}

  def before_tool_call(tool_name, arguments, actor) do
    context = [
      phase: :tool_request,
      origin: :model,
      sink: :tool,
      tool: tool_name,
      actor: actor,
      trust_zone: :semi_trusted
    ]

    case ToolGateway.guard_request(arguments, context) do
      %Decision{action: :allow} ->
        {:cont, arguments}

      %Decision{action: :redact, sanitized_text: text} when is_binary(text) ->
        {:cont, text}

      %Decision{} = denied ->
        {:halt, json_rpc_error(denied)}
    end
  end

  def after_tool_call(tool_name, result, actor) do
    context = [
      phase: :tool_result,
      origin: :tool,
      sink: :model,
      tool: tool_name,
      actor: actor,
      trust_zone: :semi_trusted
    ]

    case ToolGateway.guard_result(result, context) do
      %Decision{action: action} = decision when action in [:allow, :redact] ->
        {:cont, decision.sanitized_text || result}

      %Decision{} = denied ->
        {:halt, json_rpc_error(denied)}
    end
  end

  defp json_rpc_error(%Decision{} = decision) do
    ToolGateway.response_for_decision(decision, nil)
  end
end
```

Then call the seam from a Hermes component:

```elixir
defmodule MyApp.MCP.GuardedEcho do
  use Hermes.Server.Component, type: :tool, name: "echo"

  schema do
    field(:text, :string, required: true)
  end

  @impl true
  def execute(%{text: text} = arguments, frame) do
    actor = Map.get(frame.assigns, :actor, "anonymous")

    with {:cont, guarded_args} <-
           MyApp.MCP.SigilGuardInterceptor.before_tool_call("echo", arguments, actor),
         result <- %{text: Map.get(guarded_args, :text, text)},
         {:cont, guarded_result} <-
           MyApp.MCP.SigilGuardInterceptor.after_tool_call("echo", result, actor) do
      {:ok, guarded_result, frame}
    else
      {:halt, error} -> {:error, Jason.encode!(error), frame}
    end
  end
end
```

Register the component on the Hermes server:

```elixir
defmodule MyApp.MCPServer do
  use Hermes.Server,
    name: "MyApp MCP",
    version: "1.0.0",
    capabilities: [:tools]

  component MyApp.MCP.GuardedEcho
end
```

The important invariant is placement: guard request payloads before side
effects, and guard result payloads before model exposure.

## Plug Placement

Use a Plug before the Hermes transport when HTTP requests need early rejection,
for example to block malformed JSON-RPC tool calls before they reach the MCP
server process. This is defense in depth; the tool callback still needs the
interceptor seam because Plug cannot see every in-process tool result.

```elixir
defmodule MyAppWeb.SigilGuardMCPPlug do
  import Plug.Conn

  alias SigilGuard.{Decision, ToolGateway}

  def init(opts), do: opts

  def call(%Plug.Conn{body_params: %{"method" => "tools/call"} = body} = conn, _opts) do
    tool = get_in(body, ["params", "name"])
    arguments = get_in(body, ["params", "arguments"]) || %{}

    context = [
      phase: :tool_request,
      origin: :model,
      sink: :tool,
      tool: tool,
      actor: actor_from_conn(conn),
      trust_zone: :semi_trusted
    ]

    case ToolGateway.guard_request(arguments, context) do
      %Decision{action: action} when action in [:allow, :redact] ->
        conn

      %Decision{} = denied ->
        response = ToolGateway.response_for_decision(denied, body["id"])

        conn
        |> put_resp_content_type("application/json")
        |> send_resp(200, Jason.encode!(response))
        |> halt()
    end
  end

  def call(conn, _opts), do: conn

  defp actor_from_conn(conn) do
    conn.assigns[:actor] || List.first(get_req_header(conn, "x-sigilguard-actor"))
  end
end
```

Phoenix router placement:

```elixir
pipeline :mcp_guarded do
  plug :accepts, ["json"]
  plug MyAppWeb.SigilGuardMCPPlug
end

scope "/mcp" do
  pipe_through :mcp_guarded

  forward "/", to: Hermes.Server.Transport.StreamableHTTP.Plug,
    init_opts: [server: MyApp.MCPServer]
end
```

## Error Mapping

Always return SigilGuard denials through the SP.03 JSON-RPC error registry via
`SigilGuard.ToolGateway.response_for_decision/3`:

| Decision action | JSON-RPC status | Code |
|-----------------|-----------------|------|
| `:block` | `blocked` | `-31990` |
| `:confirm` | `confirmation_required` | `-31989` |
| `:quarantine` | `quarantined` | `-31988` |
| manifest drift | `manifest_drift` | `-31987` |
| unknown manifest | `unknown_manifest` | `-31986` |
| invalid attestation | `invalid_attestation` | `-31985` |
| sandbox required | `sandbox_required` | `-31984` |

Hermes owns transport shape. SigilGuard owns deterministic decision and error
payload content.

## MCP v2 (`2026-07-28`) Adapter Contract

The validation record above is for the named Hermes/Anubis versions; do not
infer MCP v2 support from SigilGuard. The adapter remains responsible
for protocol negotiation, `server/discover`, subscription delivery, and
constructing and validating the standard request `_meta`, including
`protocolVersion` and `clientCapabilities`.

When the adapter has negotiated the modern revision, pass it explicitly while
guarding successful results:

```elixir
SigilGuard.ToolGateway.guarded_result(result, context,
  protocol_version: "2026-07-28",
  request_action_digest: request_action_digest
)
```

This inserts `resultType: "complete"` only when absent and preserves every
existing discriminator for host-side validation. Unknown future protocol dates
are not treated as v2. Forward the full JSON-RPC request/result map to the
gateway whenever issuing confirmation or Agent Trust evidence. The shared
structured projection intentionally binds nested keys, non-string values,
client capabilities, behavior-changing extension metadata, `inputResponses`,
and `requestState`; passing only a concatenated text view loses the security
contract.

For MCP Apps, set `origin: :app` and the trusted `mcp_server` in the boundary
context. The pinned manifest must expose the tool to `"app"` and name that same
server. Verify direct `resources/read` content with
`SigilGuard.MCP.AppResource.verify/2` before the host renderer sees it. Resource
verification is limited to 1 MiB by default, and dedicated app domains require
an exact host allowlist match. Hermes or the host still owns HTML5 validation,
iframe sandboxing, CSP and Permissions Policy enforcement, and browser
permissions.

## Anubis Variant

Anubis is the maintained fork path for new deployments. The same SigilGuard
placement applies: guard in the component `execute/2` callback and before the
Streamable HTTP Plug.

```elixir
defmodule MyApp.GuardedEcho do
  use Anubis.Server.Component, type: :tool, name: "echo"

  alias Anubis.Server.Response

  schema do
    field(:text, :string, required: true)
  end

  @impl true
  def execute(%{text: text} = arguments, frame) do
    actor = Map.get(frame.assigns, :actor, "anonymous")

    with {:cont, guarded_args} <-
           MyApp.MCP.SigilGuardInterceptor.before_tool_call("echo", arguments, actor),
         result <- %{text: Map.get(guarded_args, :text, text)},
         {:cont, guarded_result} <-
           MyApp.MCP.SigilGuardInterceptor.after_tool_call("echo", result, actor) do
      {:reply, Response.json(Response.tool(), guarded_result), frame}
    else
      {:halt, error} ->
        {:reply, Response.text(Response.tool(), Jason.encode!(error)), frame}
    end
  end
end
```

## Validation Procedure

Before marking this guide complete:

1. Create a scratch project outside this repo.
2. Add the pinned `hermes_mcp` dependency and SigilGuard path dependency.
3. Add `plug` when validating the Plug placement snippet.
4. Copy the interceptor, server callback, and Plug snippets into the scratch
   project, replacing the example `MyApp.Tools.repo_file_write/1` with a stub.
5. Run `mix compile --warnings-as-errors`.
6. Repeat with `anubis_mcp` and the Anubis component snippet.
7. Record the date, Elixir/OTP versions, target package versions, and result in
   the validation record above.
