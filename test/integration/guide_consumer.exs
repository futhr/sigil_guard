# Run from an isolated consumer after compiling the guide's complete modules:
# SIGIL_GUIDE_TARGET=hermes mix run /path/to/test/integration/guide_consumer.exs
ExUnit.start()
Code.require_file(Path.expand("../support/guide_fixture.ex", __DIR__))

defmodule SigilGuard.IntegrationGuideConsumer do
  use ExUnit.Case, async: false

  @target System.fetch_env!("SIGIL_GUIDE_TARGET")
  @repo Path.expand("../..", __DIR__)

  test "the real optional framework executes the documented allowed callback" do
    case @target do
      target when target in ["hermes", "anubis"] ->
        {component, frame_module} = mcp_modules(target)

        frame =
          SigilGuard.GuideFixture.call(frame_module, :new, [
            %{actor: "fixture:actor", trust_level: :high}
          ])

        assert {:reply, response, ^frame} =
                 SigilGuard.GuideFixture.call(component, :execute, [%{text: "hello"}, frame])

        refute response.isError
        assert Jason.decode!(hd(response.content)["text"]) === %{"text" => "hello"}

      "jido" ->
        context = %{agent_id: "fixture:actor", trust_level: :medium}

        assert {:ok, %{text: "hello"}} =
                 SigilGuard.GuideFixture.call(Jido.Exec, :run, [
                   MyApp.Actions.GuardedEcho,
                   %{text: "hello"},
                   context
                 ])

      "llm" ->
        context = %{actor: "fixture:actor", trust_level: :medium}
        function = SigilGuard.GuideFixture.call(MyApp.LLM.GuardedTools, :langchain_function, [])

        assert {:ok, %{query: "docs", status: "ok"}} =
                 SigilGuard.GuideFixture.call(LangChain.Function, :execute, [
                   function,
                   %{"query" => "docs"},
                   context
                 ])

        tool = SigilGuard.GuideFixture.call(MyApp.LLM.GuardedTools, :req_llm_tool, [context])

        assert {:ok, %{query: "docs", status: "ok"}} =
                 SigilGuard.GuideFixture.call(ReqLLM.Tool, :execute, [tool, %{query: "docs"}])

        assert {:ok, %{query: "docs"}} =
                 SigilGuard.GuideFixture.call(
                   MyApp.LLM.SigilGuardPipelineStep,
                   :before_tool_call,
                   [
                     "read_file",
                     %{query: "docs"},
                     context
                   ]
                 )

      "tidewave" ->
        {request, boundary, policy} = tidewave_request(%{"count" => 1.0, "flag" => false})

        assert SigilGuard.GuideFixture.call(MyApp.TidewavePolicy, :authorize, [
                 request,
                 boundary,
                 policy
               ]) ===
                 {:ok, request}

        conn =
          SigilGuard.GuideFixture.call(Plug.Test, :conn, [
            :post,
            "/tidewave/mcp",
            Jason.encode!(request)
          ])

        parsed = %{conn | body_params: request}

        assert_raise RuntimeError, ~r/after the request body has been parsed/, fn ->
          SigilGuard.GuideFixture.call(Tidewave, :call, [
            parsed,
            SigilGuard.GuideFixture.call(Tidewave, :init, [[]])
          ])
        end
    end
  end

  test "structured redaction is refused through the actual framework callback" do
    secret = "AKIAIOSFODNN7EXAMPLE"

    case @target do
      target when target in ["hermes", "anubis"] ->
        {component, frame_module} = mcp_modules(target)
        frame = SigilGuard.GuideFixture.call(frame_module, :new, [%{trust_level: :high}])

        assert {:reply, response, ^frame} =
                 SigilGuard.GuideFixture.call(component, :execute, [%{text: secret}, frame])

        assert response.isError
        refute Jason.encode!(response.content) =~ secret

        args = [
          "read_file",
          %{text: secret},
          "fixture:actor",
          [trust_level: :high, on_sensitive: :redact]
        ]

        assert {:halt, %{"error" => %{"code" => -31_990}}} =
                 SigilGuard.GuideFixture.call(
                   MyApp.MCP.SigilGuardInterceptor,
                   :before_tool_call,
                   args
                 )

      "jido" ->
        context = %{trust_level: :high, guard_options: [on_sensitive: :redact]}

        assert {:error, {:sigil_guard_denied, :redact, _}} =
                 SigilGuard.GuideFixture.call(MyApp.Actions.GuardedEcho, :run, [
                   %{text: secret},
                   context
                 ])

        assert {:error, _} =
                 SigilGuard.GuideFixture.call(Jido.Exec, :run, [
                   MyApp.Actions.GuardedEcho,
                   %{text: secret},
                   context
                 ])

      "llm" ->
        context = %{trust_level: :high, guard_options: [on_sensitive: :redact]}
        tool = SigilGuard.GuideFixture.call(MyApp.LLM.GuardedTools, :req_llm_tool, [context])

        assert {:error, {:sigil_guard_denied, :redact, _}} =
                 SigilGuard.GuideFixture.call(ReqLLM.Tool, :execute, [tool, %{query: secret}])

        function = SigilGuard.GuideFixture.call(MyApp.LLM.GuardedTools, :langchain_function, [])

        assert {:error, reason} =
                 SigilGuard.GuideFixture.call(LangChain.Function, :execute, [
                   function,
                   %{"query" => secret},
                   context
                 ])

        assert is_binary(reason)
        refute reason =~ secret

      "tidewave" ->
        {request, boundary, policy} = tidewave_request(%{"text" => secret})
        boundary = %{boundary | trust_level: :high}

        assert {:error, %{action: :redact}} =
                 SigilGuard.GuideFixture.call(MyApp.TidewavePolicy, :authorize, [
                   request,
                   boundary,
                   policy,
                   [on_sensitive: :redact]
                 ])
    end
  end

  test "optional frameworks are not runtime dependencies of the packaged library" do
    dependencies = Application.spec(:sigil_guard, :applications)

    for app <- [:hermes_mcp, :anubis_mcp, :jido, :langchain, :req_llm, :tidewave, :bandit] do
      refute app in dependencies
    end
  end

  defp mcp_modules("hermes"), do: {MyApp.MCP.GuardedEcho, Hermes.Server.Frame}
  defp mcp_modules("anubis"), do: {MyApp.GuardedEcho, Anubis.Server.Frame}

  defp tidewave_request(arguments) do
    {:ok, policy} = SigilGuard.BoundaryPolicy.File.load(Path.join(@repo, "examples/tidewave"))

    request = %{
      "method" => "tools/call",
      "params" => %{"name" => "get_docs", "arguments" => arguments}
    }

    {request, SigilGuard.GuideFixture.boundary(request, ["read"]), policy}
  end
end
