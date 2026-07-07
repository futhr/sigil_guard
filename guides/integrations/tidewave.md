# Tidewave Integration

Validation record:

- Target package: `tidewave` `0.6.1`.
- Companion package: `bandit` `1.12.0`.
- Package metadata checked: 2026-07-07.
- Compile validation: passed on 2026-07-07 with Elixir 1.19.4 / Erlang/OTP 28.
  A scratch project compiled the SigilGuard Tidewave Plug wrapper with
  `MIX_ENV=dev mix compile --warnings-as-errors`.
- Policy validation: `examples/tidewave/SIGILGUARD_POLICY` parses with
  `SigilGuard.BoundaryPolicy.File.load/1`.

Tidewave is dev-only tooling. SigilGuard does not make Tidewave safe for
production exposure and must not be used as a reason to expose Tidewave outside
a trusted development environment. The guard below is defense in depth: it adds
deterministic policy around Tidewave's MCP tool calls for local development.

## Dependencies

For local validation:

```elixir
def deps do
  [
    {:tidewave, "~> 0.6.0", only: :dev},
    {:bandit, "~> 1.0", only: :dev},
    {:sigil_guard, path: "../sigil_guard", override: true}
  ]
end
```

The validation pin resolved to `tidewave` `0.6.1` and `bandit` `1.12.0`.

## Example Policy

This repository ships a Tidewave policy at
`examples/tidewave/SIGILGUARD_POLICY`. It:

- Blocks eval-class tools such as `project_eval`.
- Requires approval for write-class repo operations such as SQL mutation or
  file writes.
- Allows read-only docs and schema discovery tools such as `get_docs`,
  `get_source_location`, `get_ecto_schemas`, `get_ash_resources`, and
  `get_logs`.

Load it at application boot in development:

```elixir
{:ok, tidewave_policy} =
  SigilGuard.BoundaryPolicy.File.load("examples/tidewave")
```

## Plug Wrapper

Place the wrapper where you would otherwise mount `Tidewave`. The wrapper
guards JSON-RPC `tools/call` requests before forwarding to Tidewave.

```elixir
defmodule MyAppWeb.SigilGuardTidewavePlug do
  @behaviour Plug

  import Plug.Conn

  alias SigilGuard.{BoundaryPolicy, Decision, ToolGateway}

  @catalog_digest String.duplicate("0", 64)

  @impl true
  def init(opts), do: opts

  @impl true
  def call(
        %Plug.Conn{path_info: ["tidewave", "mcp" | _], body_params: %{"method" => "tools/call"} = body} =
          conn,
        opts
      ) do
    tool_name = get_in(body, ["params", "name"])
    arguments = get_in(body, ["params", "arguments"]) || %{}

    context = [
      phase: :tool_request,
      source: :model,
      origin: :model,
      sink: classify_sink(tool_name),
      tool: tidewave_tool(tool_name),
      actor: %{id: actor_from_conn(conn)},
      trust_zone: :semi_trusted,
      trust_level: :medium,
      action_digest: @catalog_digest,
      payload_digest: @catalog_digest,
      context_digest: @catalog_digest,
      sandbox: %{isolation_level: :container}
    ]

    decision =
      case Keyword.fetch(opts, :policy) do
        {:ok, %BoundaryPolicy.File{} = policy} -> BoundaryPolicy.evaluate(context, policy: policy)
        _ -> ToolGateway.guard_request(arguments, context)
      end

    case decision do
      %Decision{action: action} when action in [:allow, :redact] ->
        Tidewave.call(conn, Tidewave.init(Keyword.get(opts, :tidewave, [])))

      %Decision{} = denied ->
        response = ToolGateway.response_for_decision(denied, body["id"])

        conn
        |> put_resp_content_type("application/json")
        |> send_resp(200, Jason.encode!(response))
        |> halt()
    end
  end

  def call(conn, opts) do
    Tidewave.call(conn, Tidewave.init(Keyword.get(opts, :tidewave, [])))
  end

  defp tidewave_tool(name) do
    %{name: name, side_effects: side_effects(name), manifest_digest: @catalog_digest}
  end

  defp side_effects("project_eval"), do: ["execute"]
  defp side_effects("execute_sql_query"), do: ["write"]
  defp side_effects("write_file"), do: ["write"]
  defp side_effects("patch_file"), do: ["write"]
  defp side_effects(_), do: ["read"]

  defp classify_sink(tool) when tool in ["execute_sql_query", "write_file", "patch_file"],
    do: :repo

  defp classify_sink(_), do: :tool

  defp actor_from_conn(conn) do
    conn.assigns[:actor] || "dev-agent"
  end
end
```

`@catalog_digest` is a placeholder for the host's pinned Tidewave tool catalog
digest. Production SigilGuard surfaces should use real capability manifests;
this dev-only wrapper exists to demonstrate the policy shape.

## Phoenix Placement

In development, mount the guard instead of mounting `Tidewave` directly:

```elixir
if Mix.env() == :dev do
  {:ok, tidewave_policy} = SigilGuard.BoundaryPolicy.File.load("examples/tidewave")

  forward "/tidewave",
    MyAppWeb.SigilGuardTidewavePlug,
    policy: tidewave_policy,
    tidewave: []
end
```

## Non-Phoenix Placement

For a plain Plug/Bandit development server:

```elixir
{:ok, tidewave_policy} = SigilGuard.BoundaryPolicy.File.load("examples/tidewave")

Bandit.start_link(
  plug: {MyAppWeb.SigilGuardTidewavePlug, policy: tidewave_policy},
  port: 4000
)
```

## Validation Procedure

Before editing this guide:

1. Create a scratch project outside this repo.
2. Add `{:tidewave, "~> 0.6.0", only: :dev}`, `{:bandit, "~> 1.0", only: :dev}`,
   and the SigilGuard path dependency.
3. Copy the Plug wrapper into the scratch project.
4. Run `MIX_ENV=dev mix compile --warnings-as-errors`.
5. Run `SigilGuard.BoundaryPolicy.File.load("examples/tidewave")` in this repo.
6. Record resolved package versions, Elixir/OTP versions, and result in the
   validation record above.
