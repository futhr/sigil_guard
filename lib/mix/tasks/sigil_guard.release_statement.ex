defmodule Mix.Tasks.SigilGuard.ReleaseStatement do
  @shortdoc "Build the SP.01 release attestation statement"

  @moduledoc """
  Build the SP.01 `release` in-toto Statement binding release artifacts
  (`SP.05` D15).

  Given the built Hex tarball and the SBOM, this task computes each artifact's
  SHA-256 and emits the `https://sigilguard.dev/attestation/release/v1`
  statement whose `artifacts` list carries `{name, sha256}` entries (sorted by
  name). The release workflow signs the emitted statement with the release key
  and `gh attestation verify` gates publish.

      mix sigil_guard.release_statement \\
        --tarball dist/sigil_guard-3.0.0.tar \\
        --sbom dist/sigil_guard-3.0.0.spdx.json \\
        --output dist/sigil_guard-3.0.0.release.json
  """

  use Mix.Task

  alias SigilGuard.Attestation
  alias SigilGuard.Context
  alias SigilGuard.Decision

  @switches [
    tarball: :string,
    sbom: :string,
    package: :string,
    version: :string,
    actor: :string,
    output: :string
  ]
  @default_output "dist/release.json"
  @default_actor "urn:sigilguard:release"

  @doc false
  @spec run([String.t()]) :: :ok
  def run(args) do
    {opts, _, invalid} = OptionParser.parse(args, strict: @switches)

    if invalid != [] do
      Mix.raise("invalid options: #{inspect(invalid)}")
    end

    case statement(opts) do
      {:ok, statement} ->
        output = Keyword.get(opts, :output, @default_output)
        write_statement(output, statement)

      {:error, reason} ->
        Mix.raise("could not build release statement: #{inspect(reason)}")
    end
  end

  @doc """
  Build the release `release` statement for the tarball and SBOM in `opts`.

  Options: `:tarball` and `:sbom` (required file paths), `:package` and
  `:version` (default to the Mix project), and `:actor` (the release identity).
  """
  @spec statement(keyword()) :: {:ok, map()} | {:error, term()}
  def statement(opts) when is_list(opts) do
    with {:ok, tarball} <- fetch_path(opts, :tarball),
         {:ok, sbom} <- fetch_path(opts, :sbom),
         {:ok, artifacts} <- artifacts([tarball, sbom]) do
      payload = %{
        "package" => Keyword.get(opts, :package, project_app()),
        "version" => Keyword.get(opts, :version, project_version()),
        "artifacts" => artifacts
      }

      Attestation.from_decision(release_decision(), release_context(opts),
        payload: payload,
        statement_type: "release"
      )
    end
  end

  defp fetch_path(opts, key) do
    case Keyword.get(opts, key) do
      path when is_binary(path) and path != "" -> {:ok, path}
      _ -> {:error, {:missing_option, key}}
    end
  end

  defp artifacts(paths) do
    result =
      Enum.reduce_while(paths, {:ok, []}, fn path, {:ok, acc} ->
        case artifact(path) do
          {:ok, artifact} -> {:cont, {:ok, [artifact | acc]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)

    case result do
      {:ok, artifacts} -> {:ok, Enum.reverse(artifacts)}
      error -> error
    end
  end

  defp artifact(path) do
    case File.read(path) do
      {:ok, bytes} ->
        {:ok, %{"name" => Path.basename(path), "sha256" => sha256_hex(bytes)}}

      {:error, reason} ->
        {:error, {reason, path}}
    end
  end

  defp release_decision do
    struct!(Decision,
      verdict: :allowed,
      action: :allow,
      phase: :repo_change,
      risk_level: :low,
      trust_level: :medium
    )
  end

  # A release publishes artifacts, so it carries a `repo_change` context; the
  # `statement_type: "release"` option drives the release predicate and digest.
  defp release_context(opts) do
    actor = Keyword.get(opts, :actor, @default_actor)

    %Context{
      phase: :repo_change,
      actor: actor,
      identity: actor,
      trust_level: :medium,
      origin: :user,
      sink: :repo
    }
  end

  defp write_statement(output, statement) do
    output
    |> Path.dirname()
    |> File.mkdir_p!()

    File.write!(output, Jason.encode_to_iodata!(statement, pretty: true))
    Mix.shell().info("Wrote release statement to #{output}")
  end

  defp project_app, do: to_string(Mix.Project.config()[:app])
  defp project_version, do: Mix.Project.config()[:version]
  defp sha256_hex(data), do: Base.encode16(:crypto.hash(:sha256, data), case: :lower)
end
