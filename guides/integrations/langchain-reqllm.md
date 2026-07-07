# LangChain And ReqLLM Integration

Validation record:

- Target packages: `langchain` `0.8.14`, `req_llm` `1.17.1`.
- Package metadata checked: 2026-07-07.
- Compile validation: passed on 2026-07-07 with Elixir 1.19.4 / Erlang/OTP 28.
  A scratch project compiled the guarded LangChain function and ReqLLM tool
  examples with `mix compile --warnings-as-errors`.

LangChain and ReqLLM both expose tool/function callbacks that execute host
code on behalf of a model. SigilGuard belongs inside those callbacks: guard the
request arguments before side effects, then guard the tool result before it is
returned to model context.

## Dependencies

For local validation, pin both packages and use the SigilGuard checkout as a
path dependency:

```elixir
def deps do
  [
    {:langchain, "~> 0.8"},
    {:req_llm, "~> 1.17"},
    {:sigil_guard, path: "../sigil_guard", override: true}
  ]
end
```

The validation pin resolved to `langchain` `0.8.14` and `req_llm` `1.17.1`.

## Shared Gate Module

Keep the SigilGuard boundary logic in a small module that both callback systems
can call.

```elixir
defmodule MyApp.LLM.GuardedTools do
  alias LangChain.Function
  alias ReqLLM.Tool
  alias SigilGuard.{Decision, ToolGateway}

  def langchain_function do
    Function.new!(%{
      name: "repo_lookup",
      description: "Looks up repository data after SigilGuard gating",
      function: fn args, context -> guarded_lookup(args, context) end
    })
  end

  def req_llm_tool do
    ReqLLM.tool(
      name: "repo_lookup",
      description: "Looks up repository data after SigilGuard gating",
      parameters: [query: [type: :string, required: true, doc: "Lookup query"]],
      callback: fn args -> guarded_lookup(args, %{}) end
    )
  end

  def execute_req_llm_tool(args) do
    req_llm_tool()
    |> Tool.execute(args)
    |> guard_result("repo_lookup", %{})
  end

  def guarded_lookup(args, context) do
    actor = Map.get(context, :actor) || Map.get(context, "actor") || "anonymous"

    boundary = [
      phase: :tool_request,
      origin: :model,
      sink: :tool,
      tool: "repo_lookup",
      actor: actor,
      trust_zone: :semi_trusted
    ]

    case ToolGateway.guard_request(args, boundary) do
      %Decision{action: action} when action in [:allow, :redact] ->
        result = %{query: Map.get(args, :query) || Map.get(args, "query"), status: "ok"}
        guard_result({:ok, result}, "repo_lookup", context)

      %Decision{} = denied ->
        {:error, {:sigil_guard_denied, denied.action, denied.reason}}
    end
  end

  def guard_result({:ok, result}, tool_name, context) do
    actor = Map.get(context, :actor) || Map.get(context, "actor") || "anonymous"

    boundary = [
      phase: :tool_result,
      origin: :tool,
      sink: :model,
      tool: tool_name,
      actor: actor,
      trust_zone: :semi_trusted
    ]

    case ToolGateway.guard_result(result, boundary) do
      %Decision{action: action} = decision when action in [:allow, :redact] ->
        {:ok, decision.sanitized_text || result}

      %Decision{} = denied ->
        {:error, {:sigil_guard_denied, denied.action, denied.reason}}
    end
  end

  def guard_result(error, _tool_name, _context), do: error
end
```

## LangChain Placement

Register the guarded function on the chain the same way you register any other
`LangChain.Function`. The callback receives model-supplied arguments, so it is
the pre-execution gate.

```elixir
alias LangChain.Chains.LLMChain

chain =
  %{llm: llm}
  |> LLMChain.new!()
  |> LLMChain.add_tools([MyApp.LLM.GuardedTools.langchain_function()])
```

If your host stores actor identity in chain context, pass it to the function
callback as `context["actor"]` or `context[:actor]` so SigilGuard evidence can
name the actor.

## ReqLLM Placement

ReqLLM tools use callbacks directly. Use the same guarded callback and expose it
as a `ReqLLM.Tool`.

```elixir
tool = MyApp.LLM.GuardedTools.req_llm_tool()

{:ok, result} =
  tool
  |> ReqLLM.Tool.execute(%{query: "docs"})
  |> MyApp.LLM.GuardedTools.guard_result("repo_lookup", %{actor: "agent:researcher"})
```

For normal generation, include the tool in the provider options your host
already passes to ReqLLM:

```elixir
ReqLLM.generate_text(
  "anthropic:claude-sonnet-4-5-20250929",
  "Look up the release notes",
  tools: [tool]
)
```

## ReqLLM Pipeline-Step Variant

Hosts that wrap ReqLLM in a pipeline can split the two gates into named steps:

```elixir
defmodule MyApp.LLM.SigilGuardPipelineStep do
  def before_tool_call(tool_name, args, context) do
    MyApp.LLM.GuardedTools.guarded_lookup(args, Map.put(context, :tool, tool_name))
  end

  def after_tool_call(tool_name, result, context) do
    MyApp.LLM.GuardedTools.guard_result({:ok, result}, tool_name, context)
  end
end
```

The step still follows the same invariant: gate model-to-tool arguments before
side effects and tool-to-model results before model exposure.

## Denial Handling

Both LangChain and ReqLLM callbacks can return ordinary `{:error, reason}`
tuples:

```elixir
{:error, {:sigil_guard_denied, :quarantine, "prompt injection indicators found"}}
```

Hosts that surface the denial over MCP can convert the same decision with
`SigilGuard.ToolGateway.response_for_decision/3`.

## Validation Procedure

Before editing this guide:

1. Create a scratch project outside this repo.
2. Add `{:langchain, "~> 0.8"}`, `{:req_llm, "~> 1.17"}`, and the SigilGuard
   path dependency.
3. Copy the shared gate module into the scratch project.
4. Run `mix compile --warnings-as-errors`.
5. Record resolved package versions, Elixir/OTP versions, and result in the
   validation record above.
