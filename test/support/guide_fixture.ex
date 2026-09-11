defmodule SigilGuard.GuideFixture do
  @moduledoc false

  @root Path.expand("../..", __DIR__)

  @doc false
  @spec call(module(), atom(), [term()]) :: term()
  def call(module, function, arguments), do: apply(module, function, arguments)

  @doc false
  @spec compile(String.t(), module()) :: :ok
  def compile(guide, module) do
    path = Path.join([@root, "guides", "integrations", guide <> ".md"])
    prefix = "defmodule " <> inspect(module) <> " do"

    [source] =
      ~r/```elixir\n(.*?)\n```/s
      |> Regex.scan(File.read!(path), capture: :all_but_first)
      |> Enum.map(&hd/1)
      |> Enum.filter(&String.starts_with?(&1, prefix))

    Code.compile_string(source, path)
    :ok
  end

  @doc false
  @spec boundary(map(), [String.t()]) :: SigilGuard.Boundary.t()
  def boundary(request, effects) do
    {:ok, digest} = SigilGuard.Attestation.Digest.payload_digest(request)

    SigilGuard.Boundary.new(%{
      phase: :tool_request,
      source: :model,
      origin: :model,
      sink: if(effects == ["write"], do: :repo, else: :tool),
      actor: %{"id" => "fixture:actor"},
      tool: %{
        "name" => get_in(request, ["params", "name"]),
        "side_effects" => effects,
        "manifest_digest" => String.duplicate("a", 64)
      },
      trust_level: :medium,
      trust_zone: :semi_trusted,
      action_digest: String.duplicate("a", 64),
      payload_digest: digest,
      context_digest: String.duplicate("a", 64),
      sandbox: %{isolation_level: :container}
    })
  end
end
