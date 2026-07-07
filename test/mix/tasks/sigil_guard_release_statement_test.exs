defmodule Mix.Tasks.SigilGuard.ReleaseStatementTest do
  @moduledoc false

  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias Mix.Tasks.SigilGuard.ReleaseStatement
  alias SigilGuard.TrustProfile

  defp action_digest(statement) do
    statement["subject"]
    |> Enum.find(&(&1["name"] == "action"))
    |> get_in(["digest", "sha256"])
  end

  defp write_artifacts(tarball_body \\ "tarball bytes") do
    tarball = tmp_path("tar")
    sbom = tmp_path("spdx")
    File.write!(tarball, tarball_body)
    File.write!(sbom, ~s({"spdxVersion":"SPDX-2.3"}))
    {tarball, sbom}
  end

  describe "statement/1" do
    test "builds a profile-valid release statement binding the artifacts" do
      {tarball, sbom} = write_artifacts()

      assert {:ok, statement} =
               ReleaseStatement.statement(
                 tarball: tarball,
                 sbom: sbom,
                 package: "sigil_guard",
                 version: "1.0.0"
               )

      assert statement["predicateType"] == "https://sigilguard.dev/attestation/release/v1"
      assert statement["predicate"]["statement_type"] == "release"
      assert TrustProfile.validate(statement) == {:ok, statement}
      assert is_binary(action_digest(statement))
    end

    test "the action digest binds the artifact contents" do
      {tarball_a, sbom} = write_artifacts("release A")
      {tarball_b, _} = write_artifacts("release B")

      {:ok, a} = ReleaseStatement.statement(tarball: tarball_a, sbom: sbom, version: "1.0.0")
      {:ok, b} = ReleaseStatement.statement(tarball: tarball_b, sbom: sbom, version: "1.0.0")

      # Different tarball bytes yield a different release action digest.
      refute action_digest(a) == action_digest(b)
    end

    test "defaults package and version to the Mix project" do
      {tarball, sbom} = write_artifacts()
      assert {:ok, _} = ReleaseStatement.statement(tarball: tarball, sbom: sbom)
    end

    test "fails on missing options or unreadable files" do
      {tarball, sbom} = write_artifacts()

      assert ReleaseStatement.statement(sbom: sbom) == {:error, {:missing_option, :tarball}}
      assert ReleaseStatement.statement(tarball: tarball) == {:error, {:missing_option, :sbom}}

      gone = tmp_path("gone")
      assert ReleaseStatement.statement(tarball: gone, sbom: sbom) == {:error, {:enoent, gone}}
    end
  end

  describe "run/1" do
    test "writes the release statement to the output path" do
      {tarball, sbom} = write_artifacts()
      output = tmp_path("release")

      capture_io(fn ->
        ReleaseStatement.run(["--tarball", tarball, "--sbom", sbom, "--output", output])
      end)

      assert {:ok, decoded} = Jason.decode(File.read!(output))
      assert decoded["predicateType"] == "https://sigilguard.dev/attestation/release/v1"
    end

    test "raises on invalid options" do
      assert_raise Mix.Error, ~r/invalid options/, fn ->
        ReleaseStatement.run(["--bogus", "x"])
      end
    end

    test "raises when the statement cannot be built" do
      {_, sbom} = write_artifacts()

      assert_raise Mix.Error, ~r/could not build release statement/, fn ->
        ReleaseStatement.run(["--sbom", sbom])
      end
    end
  end

  defp tmp_path(label) do
    path =
      System.tmp_dir!()
      |> Path.join("sigil_guard_release_statement_#{label}_#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm(path) end)
    path
  end
end
