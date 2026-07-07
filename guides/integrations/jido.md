# Jido Integration

Validation record:

- Target package: `jido` `2.3.2`.
- Package metadata checked: 2026-07-07.
- Compile validation: passed on 2026-07-07 with Elixir 1.19.4 / Erlang/OTP 28.
  A scratch project compiled the guarded Jido action with
  `mix compile --warnings-as-errors`.

Jido actions are a natural SigilGuard insertion point: guard the action input
inside `run/2` before side effects, thread the agent identity into the boundary
context, and return a normal Jido action error when SigilGuard denies the
operation. Do not raise for policy denials.

## Dependencies

For local validation, pin Jido and use the SigilGuard checkout as a path
dependency:

```elixir
def deps do
  [
    {:jido, "~> 2.3.2"},
    {:sigil_guard, path: "../sigil_guard", override: true}
  ]
end
```

## Guarded Action

Wrap effectful action execution in a SigilGuard request gate. The action
returns `{:error, reason}` on denial, preserving Jido's action error contract.

```elixir
defmodule MyApp.Actions.GuardedEcho do
  use Jido.Action,
    name: "guarded_echo",
    description: "Echoes text after SigilGuard gating",
    category: "security",
    tags: ["sigil_guard", "tool"],
    vsn: "1.0.0",
    schema: [
      text: [type: :string, required: true, doc: "Text to echo"]
    ],
    output_schema: [
      text: [type: :string, required: true]
    ]

  alias SigilGuard.{Decision, ToolGateway}

  @impl true
  def run(%{text: text} = params, context) do
    actor = Map.get(context, :agent_id) || Map.get(context, "agent_id") || "anonymous"

    boundary = [
      phase: :tool_request,
      origin: :model,
      sink: :tool,
      tool: "guarded_echo",
      actor: actor,
      trust_zone: :semi_trusted
    ]

    case ToolGateway.guard_request(params, boundary) do
      %Decision{action: action} when action in [:allow, :redact] ->
        {:ok, %{text: text}}

      %Decision{} = denied ->
        {:error, {:sigil_guard_denied, denied.action, denied.reason}}
    end
  end
end
```

## Actor Context

Populate `:actor` from the Jido agent identity or runtime context. The value
should be stable enough to appear in attestations and audit evidence.

```elixir
context = %{
  agent_id: "spiffe://example.test/agents/researcher",
  tenant_id: "tenant-123"
}

Jido.Action.Exec.run(MyApp.Actions.GuardedEcho, %{text: "hello"}, context)
```

If your host uses a different identity shape, normalize it before calling the
action:

```elixir
context =
  context
  |> Map.put(:agent_id, MyApp.Identity.to_actor_id(agent))
  |> Map.put(:trust_zone, :semi_trusted)
```

## Result Gate

For actions that fetch or synthesize content that will be shown to a model,
also guard the result before returning it:

```elixir
defp release_result(tool_name, result, context) do
  actor = Map.get(context, :agent_id) || "anonymous"

  boundary = [
    phase: :tool_result,
    origin: :tool,
    sink: :model,
    tool: tool_name,
    actor: actor,
    trust_zone: Map.get(context, :trust_zone, :semi_trusted)
  ]

  case SigilGuard.ToolGateway.guard_result(result, boundary) do
    %SigilGuard.Decision{action: action} = decision when action in [:allow, :redact] ->
      {:ok, decision.sanitized_text || result}

    %SigilGuard.Decision{} = denied ->
      {:error, {:sigil_guard_denied, denied.action, denied.reason}}
  end
end
```

## Denial Handling

Map SigilGuard denials to ordinary Jido action errors:

```elixir
{:error, {:sigil_guard_denied, :block, "untrusted zone may not request tools"}}
```

This lets the agent runtime decide whether to retry, ask for approval, or halt
without crashing the action process. Hosts that expose Jido actions as MCP tools
can convert the same decision to JSON-RPC with
`SigilGuard.ToolGateway.response_for_decision/3`.

## Validation Procedure

Before editing this guide:

1. Create a scratch project outside this repo.
2. Add `{:jido, "~> 2.3.2"}` and the SigilGuard path dependency.
3. Copy the guarded action example into the scratch project.
4. Run `mix compile --warnings-as-errors`.
5. Record the Elixir/OTP versions, Jido version, and result in the validation
   record above.
