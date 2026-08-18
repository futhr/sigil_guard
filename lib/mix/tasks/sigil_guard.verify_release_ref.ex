defmodule Mix.Tasks.SigilGuard.VerifyReleaseRef do
  @shortdoc "Verify the release tag, project version, and checkout identity"

  @moduledoc """
  Verify that a release runs from the exact tag for the Mix project version.

  In GitHub Actions, `GITHUB_REF`, `GITHUB_REF_NAME`, and `GITHUB_SHA` are
  checked together: the expected tag must resolve to the triggering commit and
  the checked-out `HEAD`. For a local preflight, setting only
  `GITHUB_REF_NAME=v<version>` validates the tag name without requiring the tag
  to exist locally.

      GITHUB_REF_NAME=v1.0.0 mix sigil_guard.verify_release_ref
  """

  use Mix.Task

  @sha_pattern ~r/\A[0-9a-f]{40}\z/

  @type verify_error ::
          :invalid_environment
          | :missing_ref_name
          | :incomplete_github_identity
          | :invalid_github_sha
          | {:unexpected_ref_name, String.t(), String.t()}
          | {:unexpected_ref, String.t(), String.t()}
          | {:cannot_resolve, String.t(), String.t()}
          | {:tag_sha_mismatch, String.t(), String.t()}
          | {:head_sha_mismatch, String.t(), String.t()}

  @doc false
  @spec run([String.t()]) :: :ok
  def run([]) do
    version = Mix.Project.config() |> Keyword.fetch!(:version)

    case verify(version, System.get_env(), File.cwd!()) do
      :ok -> Mix.shell().info("Verified release ref v#{version}")
      {:error, reason} -> Mix.raise("release ref verification failed: #{inspect(reason)}")
    end
  end

  def run(_), do: Mix.raise("sigil_guard.verify_release_ref does not accept arguments")

  @doc """
  Verify release identity from an environment map and Git repository.

  Supplying only `GITHUB_REF_NAME` performs a local name preflight. Supplying
  either `GITHUB_REF` or `GITHUB_SHA` enables strict CI verification and
  requires both values.
  """
  @spec verify(String.t(), %{String.t() => String.t()}, Path.t()) ::
          :ok | {:error, verify_error()}
  def verify(version, environment, repository \\ ".")

  def verify(version, environment, repository)
      when is_binary(version) and is_map(environment) and is_binary(repository) do
    expected_name = "v#{version}"
    expected_ref = "refs/tags/#{expected_name}"

    with {:ok, ref_name} <- fetch_ref_name(environment),
         :ok <- require_equal(ref_name, expected_name, :ref_name) do
      verify_git_identity(environment, repository, expected_ref)
    end
  end

  def verify(_, _, _), do: {:error, :invalid_environment}

  defp fetch_ref_name(environment) do
    case Map.get(environment, "GITHUB_REF_NAME") do
      ref_name when is_binary(ref_name) and ref_name != "" -> {:ok, ref_name}
      _ -> {:error, :missing_ref_name}
    end
  end

  defp require_equal(value, value, _), do: :ok

  defp require_equal(actual, expected, :ref_name) do
    {:error, {:unexpected_ref_name, expected, actual}}
  end

  defp require_equal(actual, expected, :ref) do
    {:error, {:unexpected_ref, expected, actual}}
  end

  defp verify_git_identity(environment, repository, expected_ref) do
    case {Map.get(environment, "GITHUB_REF"), Map.get(environment, "GITHUB_SHA")} do
      {nil, nil} ->
        :ok

      {github_ref, github_sha} when is_binary(github_ref) and is_binary(github_sha) ->
        verify_git_identity(repository, expected_ref, github_ref, github_sha)

      _ ->
        {:error, :incomplete_github_identity}
    end
  end

  defp verify_git_identity(repository, expected_ref, github_ref, github_sha) do
    with :ok <- require_equal(github_ref, expected_ref, :ref),
         :ok <- validate_sha(github_sha),
         {:ok, tag_sha} <- resolve_commit(repository, expected_ref),
         :ok <- compare_sha(tag_sha, github_sha, :tag),
         {:ok, head_sha} <- resolve_commit(repository, "HEAD") do
      compare_sha(head_sha, github_sha, :head)
    end
  end

  defp validate_sha(sha) do
    if Regex.match?(@sha_pattern, sha), do: :ok, else: {:error, :invalid_github_sha}
  end

  defp compare_sha(sha, sha, _), do: :ok

  defp compare_sha(actual, expected, :tag),
    do: {:error, {:tag_sha_mismatch, expected, actual}}

  defp compare_sha(actual, expected, :head),
    do: {:error, {:head_sha_mismatch, expected, actual}}

  defp resolve_commit(repository, ref) do
    options = [
      stderr_to_stdout: true,
      env: [
        {"CODECOV_TOKEN", nil},
        {"GH_TOKEN", nil},
        {"GITHUB_TOKEN", nil},
        {"HEX_API_KEY", nil}
      ]
    ]

    case System.cmd(
           "git",
           ["-C", repository, "rev-parse", "--verify", "#{ref}^{commit}"],
           options
         ) do
      {sha, 0} -> {:ok, String.trim(sha)}
      {output, _} -> {:error, {:cannot_resolve, ref, String.trim(output)}}
    end
  end
end
