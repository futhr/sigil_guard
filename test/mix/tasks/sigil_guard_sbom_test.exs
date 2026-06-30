defmodule Mix.Tasks.SigilGuard.SbomTest do
  @moduledoc false

  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias Mix.Tasks.SigilGuard.Sbom

  @created_at "2026-06-30T12:00:00Z"
  @git_revision String.duplicate("a", 40)

  describe "generate/1" do
    test "builds an SPDX 2.3 document from the project and lockfile" do
      sbom = Sbom.generate(created_at: @created_at, git_revision: @git_revision)

      assert sbom["spdxVersion"] == "SPDX-2.3"
      assert sbom["dataLicense"] == "CC0-1.0"
      assert sbom["SPDXID"] == "SPDXRef-DOCUMENT"
      assert sbom["creationInfo"]["created"] == @created_at

      package_names = MapSet.new(sbom["packages"], & &1["name"])

      assert Enum.any?(sbom["packages"], fn package ->
               package["name"] == "sigil_guard" and
                 package["externalRefs"] == [
                   %{
                     "referenceCategory" => "PACKAGE-MANAGER",
                     "referenceType" => "purl",
                     "referenceLocator" => "pkg:hex/sigil_guard@0.2.0"
                   }
                 ]
             end)

      assert Enum.any?(sbom["packages"], fn package ->
               package["name"] == "jason" and package["versionInfo"] == "1.4.5"
             end)

      assert MapSet.member?(package_names, "finch")
      assert MapSet.member?(package_names, "mint")
      refute MapSet.member?(package_names, "credo")
      refute MapSet.member?(package_names, "benchee")

      assert direct_dependency_ids(sbom) ==
               MapSet.new([
                 "SPDXRef-Package-finch",
                 "SPDXRef-Package-jason",
                 "SPDXRef-Package-telemetry"
               ])

      assert Enum.any?(sbom["relationships"], fn relationship ->
               relationship["spdxElementId"] == "SPDXRef-Package-finch" and
                 relationship["relationshipType"] == "DEPENDS_ON" and
                 relationship["relatedSpdxElement"] == "SPDXRef-Package-mint"
             end)
    end
  end

  describe "run/1" do
    test "writes pretty JSON to the selected output path" do
      output =
        Path.join(System.tmp_dir!(), "sigil_guard_sbom_test_#{System.unique_integer()}.json")

      on_exit(fn -> File.rm(output) end)

      capture_io(fn ->
        Sbom.run(["--output", output])
      end)

      assert File.exists?(output)

      decoded =
        output
        |> File.read!()
        |> Jason.decode!()

      assert decoded["spdxVersion"] == "SPDX-2.3"
    end
  end

  defp direct_dependency_ids(sbom) do
    sbom["relationships"]
    |> Enum.filter(fn relationship ->
      relationship["spdxElementId"] == "SPDXRef-Package-sigil-guard" and
        relationship["relationshipType"] == "DEPENDS_ON"
    end)
    |> Enum.map(& &1["relatedSpdxElement"])
    |> MapSet.new()
  end
end
