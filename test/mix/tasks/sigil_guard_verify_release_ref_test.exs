defmodule Mix.Tasks.SigilGuard.VerifyReleaseRefTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias Mix.Tasks.SigilGuard.VerifyReleaseRef

  setup do
    repository =
      Path.join(
        System.tmp_dir!(),
        "sigil_guard_release_ref_#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(repository)
    git!(repository, ["init", "--quiet"])
    git!(repository, ["config", "user.email", "release-test@example.invalid"])
    git!(repository, ["config", "user.name", "Release Test"])
    File.write!(Path.join(repository, "release.txt"), "first\n")
    git!(repository, ["add", "release.txt"])
    git!(repository, ["commit", "--quiet", "-m", "first"])
    sha = git!(repository, ["rev-parse", "HEAD"])
    git!(repository, ["tag", "v1.0.0"])

    on_exit(fn -> File.rm_rf!(repository) end)

    %{environment: release_environment(sha), repository: repository, sha: sha}
  end

  test "accepts the exact version tag at the triggering checkout", context do
    assert :ok =
             VerifyReleaseRef.verify("1.0.0", context.environment, context.repository)
  end

  test "accepts an exact tag-name-only local preflight", context do
    assert :ok =
             VerifyReleaseRef.verify(
               "1.0.0",
               %{"GITHUB_REF_NAME" => "v1.0.0"},
               context.repository
             )
  end

  test "rejects a branch or version-mismatched tag", context do
    branch = Map.put(context.environment, "GITHUB_REF_NAME", "main")
    wrong_version = Map.put(context.environment, "GITHUB_REF_NAME", "v2.0.0")

    assert {:error, {:unexpected_ref_name, "v1.0.0", "main"}} =
             VerifyReleaseRef.verify("1.0.0", branch, context.repository)

    assert {:error, {:unexpected_ref_name, "v1.0.0", "v2.0.0"}} =
             VerifyReleaseRef.verify("1.0.0", wrong_version, context.repository)
  end

  test "rejects an unexpected full ref", context do
    environment = Map.put(context.environment, "GITHUB_REF", "refs/heads/main")

    assert {:error, {:unexpected_ref, "refs/tags/v1.0.0", "refs/heads/main"}} =
             VerifyReleaseRef.verify("1.0.0", environment, context.repository)
  end

  test "rejects incomplete or malformed GitHub identity", context do
    incomplete = Map.delete(context.environment, "GITHUB_SHA")
    malformed = Map.put(context.environment, "GITHUB_SHA", "not-a-sha")

    assert {:error, :incomplete_github_identity} =
             VerifyReleaseRef.verify("1.0.0", incomplete, context.repository)

    assert {:error, :invalid_github_sha} =
             VerifyReleaseRef.verify("1.0.0", malformed, context.repository)
  end

  test "rejects a tag that does not resolve to the triggering SHA", context do
    File.write!(Path.join(context.repository, "release.txt"), "second\n")
    git!(context.repository, ["add", "release.txt"])
    git!(context.repository, ["commit", "--quiet", "-m", "second"])
    second_sha = git!(context.repository, ["rev-parse", "HEAD"])
    environment = release_environment(second_sha)
    tag_sha = context.sha

    assert {:error, {:tag_sha_mismatch, ^second_sha, ^tag_sha}} =
             VerifyReleaseRef.verify("1.0.0", environment, context.repository)
  end

  test "rejects a checkout that differs from the triggering SHA", context do
    File.write!(Path.join(context.repository, "release.txt"), "second\n")
    git!(context.repository, ["add", "release.txt"])
    git!(context.repository, ["commit", "--quiet", "-m", "second"])
    head_sha = git!(context.repository, ["rev-parse", "HEAD"])
    triggering_sha = context.sha

    assert {:error, {:head_sha_mismatch, ^triggering_sha, ^head_sha}} =
             VerifyReleaseRef.verify("1.0.0", context.environment, context.repository)
  end

  defp release_environment(sha) do
    %{
      "GITHUB_REF" => "refs/tags/v1.0.0",
      "GITHUB_REF_NAME" => "v1.0.0",
      "GITHUB_SHA" => sha
    }
  end

  defp git!(repository, arguments) do
    options = [
      stderr_to_stdout: true,
      env: [
        {"CODECOV_TOKEN", nil},
        {"GH_TOKEN", nil},
        {"GITHUB_TOKEN", nil},
        {"HEX_API_KEY", nil}
      ]
    ]

    case System.cmd("git", ["-C", repository | arguments], options) do
      {output, 0} -> String.trim(output)
      {output, status} -> flunk("git failed with status #{status}: #{output}")
    end
  end
end
