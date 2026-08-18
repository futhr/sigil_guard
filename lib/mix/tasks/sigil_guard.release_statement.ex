defmodule Mix.Tasks.SigilGuard.ReleaseStatement do
  @shortdoc "Build the release attestation statement"

  @moduledoc """
  Build the `release` in-toto Statement binding release artifacts.

  Given the built Hex tarball and the SBOM, this task computes each artifact's
  SHA-256 and emits the `https://sigilguard.dev/attestation/release/v1`
  statement. Its `predicate.release` object directly names the package,
  semantic version, and sorted `{name, sha256}` artifact entries. The release
  workflow signs that predicate against both artifact subjects, and
  `gh attestation verify` gates publish.

      mix sigil_guard.release_statement \\
        --tarball dist/sigil_guard-1.0.0.tar \\
        --sbom dist/sigil_guard-1.0.0.spdx.json \\
        --output dist/sigil_guard-1.0.0.release.json
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
  semantic `:version` (default to the Mix project), and `:actor` (the release
  identity).
  """
  @spec statement(keyword()) :: {:ok, map()} | {:error, term()}
  def statement(opts) when is_list(opts) do
    with {:ok, tarball} <- fetch_path(opts, :tarball),
         {:ok, sbom} <- fetch_path(opts, :sbom),
         {:ok, artifacts} <- artifacts([tarball, sbom]),
         {:ok, package} <- release_package(opts),
         {:ok, version} <- release_version(opts) do
      payload = %{
        "package" => package,
        "version" => version,
        "artifacts" => artifacts
      }

      with {:ok, statement} <-
             Attestation.from_decision(release_decision(), release_context(opts),
               payload: payload,
               statement_type: "release"
             ) do
        {:ok, put_in(statement, ["predicate", "release"], payload)}
      end
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
      {:ok, artifacts} -> {:ok, Enum.sort_by(artifacts, & &1["name"])}
      error -> error
    end
  end

  defp release_package(opts) do
    case Keyword.get(opts, :package, project_app()) do
      package when is_binary(package) and package != "" -> {:ok, package}
      _ -> {:error, {:invalid_option, :package}}
    end
  end

  defp release_version(opts) do
    case Keyword.get(opts, :version, project_version()) do
      version when is_binary(version) ->
        case Version.parse(version) do
          {:ok, _} -> {:ok, version}
          :error -> {:error, {:invalid_option, :version}}
        end

      _ ->
        {:error, {:invalid_option, :version}}
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
