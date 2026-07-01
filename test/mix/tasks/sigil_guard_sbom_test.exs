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

  describe "verify_document/1" do
    test "accepts the generated SPDX document shape for the current project" do
      sbom = Sbom.generate(created_at: @created_at, git_revision: @git_revision)

      assert :ok = Sbom.verify_document(sbom)
    end

    test "rejects invalid SPDX metadata" do
      sbom =
        [created_at: @created_at, git_revision: @git_revision]
        |> Sbom.generate()
        |> Map.put("spdxVersion", "SPDX-2.2")

      assert {:error, :invalid_spdx_version} = Sbom.verify_document(sbom)
    end

    test "rejects documents without the expected root package" do
      sbom =
        [created_at: @created_at, git_revision: @git_revision]
        |> Sbom.generate()
        |> Map.put("packages", [])

      assert {:error, :missing_root_package} = Sbom.verify_document(sbom)
    end

    test "rejects documents without the root DESCRIBES relationship" do
      sbom =
        [created_at: @created_at, git_revision: @git_revision]
        |> Sbom.generate()
        |> Map.put("relationships", [])

      assert {:error, :missing_describes_relationship} = Sbom.verify_document(sbom)
    end

    test "rejects tampered dependency packages" do
      sbom =
        [created_at: @created_at, git_revision: @git_revision]
        |> Sbom.generate()
        |> update_in(["packages"], fn packages ->
          Enum.map(packages, fn
            %{"name" => "jason"} = package -> %{package | "versionInfo" => "9.9.9"}
            package -> package
          end)
        end)

      assert {:error, :invalid_dependency_package} = Sbom.verify_document(sbom)
    end

    test "rejects missing dependency packages" do
      sbom =
        [created_at: @created_at, git_revision: @git_revision]
        |> Sbom.generate()
        |> update_in(["packages"], fn packages ->
          Enum.reject(packages, &(&1["name"] == "jason"))
        end)

      assert {:error, :missing_dependency_package} = Sbom.verify_document(sbom)
    end

    test "rejects missing dependency relationships" do
      sbom =
        [created_at: @created_at, git_revision: @git_revision]
        |> Sbom.generate()
        |> update_in(["relationships"], fn relationships ->
          Enum.reject(relationships, fn relationship ->
            relationship["spdxElementId"] == "SPDXRef-Package-sigil-guard" and
              relationship["relationshipType"] == "DEPENDS_ON" and
              relationship["relatedSpdxElement"] == "SPDXRef-Package-jason"
          end)
        end)

      assert {:error, :missing_dependency_relationship} = Sbom.verify_document(sbom)
    end
  end

  describe "verify_file/1" do
    test "accepts valid JSON SPDX files" do
      output = tmp_path("valid")
      sbom = Sbom.generate(created_at: @created_at, git_revision: @git_revision)

      File.write!(output, Jason.encode!(sbom))

      assert :ok = Sbom.verify_file(output)
    end

    test "rejects invalid JSON and missing files" do
      output = tmp_path("invalid")

      File.write!(output, "{")

      assert {:error, :invalid_json} = Sbom.verify_file(output)
      assert {:error, :enoent} = Sbom.verify_file(tmp_path("missing"))
    end
  end

  describe "run/1" do
    test "writes pretty JSON to the selected output path" do
      output = tmp_path("write")

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

    test "verifies an existing SBOM file" do
      output = tmp_path("verify")

      capture_io(fn ->
        Sbom.run(["--output", output])
      end)

      assert capture_io(fn ->
               Sbom.run(["--verify", output])
             end) =~ "Verified SBOM"
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

  defp tmp_path(label) do
    path =
      System.tmp_dir!()
      |> Path.join("sigil_guard_sbom_test_#{label}_#{System.unique_integer()}.json")

    on_exit(fn -> File.rm(path) end)
    path
  end
end
