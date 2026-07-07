defmodule Mix.Tasks.SigilGuard.SbomTest do
  @moduledoc false

  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Mix.Tasks.SigilGuard.Sbom

  @created_at "2026-06-30T12:00:00Z"
  @git_revision String.duplicate("a", 40)

  defmodule TwoTupleKeywordProject do
    @moduledoc false

    @spec project() :: keyword()
    def project do
      [
        app: :sigil_guard_sbom_fixture,
        version: "1.0.0",
        source_url: "https://example.invalid/sigil_guard_sbom_fixture",
        package: [
          name: "sigil_guard_sbom_fixture",
          licenses: ["MIT"]
        ],
        deps: [
          {:jason, "~> 1.4"},
          {:credo, only: [:dev, :test], runtime: false}
        ]
      ]
    end
  end

  defmodule MissingRuntimeLockProject do
    @moduledoc false

    @spec project() :: keyword()
    def project do
      [
        app: :sigil_guard_sbom_fixture,
        version: "1.0.0",
        source_url: "https://example.invalid/sigil_guard_sbom_fixture",
        package: [
          name: "sigil_guard_sbom_fixture",
          licenses: ["MIT"]
        ],
        deps: [
          {:jason, "~> 1.4"},
          {:not_locked, "~> 0.1"}
        ]
      ]
    end
  end

  defmodule RuntimePathProject do
    @moduledoc false

    @spec project() :: keyword()
    def project do
      [
        app: :sigil_guard_sbom_fixture,
        version: "1.0.0",
        source_url: "https://example.invalid/sigil_guard_sbom_fixture",
        package: [
          name: "sigil_guard_sbom_fixture",
          licenses: ["MIT"]
        ],
        deps: [
          {:jason, "~> 1.4"},
          {:local_runtime, path: "../local_runtime"}
        ]
      ]
    end
  end

  defmodule NonRuntimePathProject do
    @moduledoc false

    @spec project() :: keyword()
    def project do
      [
        app: :sigil_guard_sbom_fixture,
        version: "1.0.0",
        source_url: "https://example.invalid/sigil_guard_sbom_fixture",
        package: [
          name: "sigil_guard_sbom_fixture",
          licenses: ["MIT"]
        ],
        deps: [
          {:jason, "~> 1.4"},
          {:local_dev, path: "../local_dev", only: :dev, runtime: false}
        ]
      ]
    end
  end

  defmodule RuntimeGithubProject do
    @moduledoc false

    @spec project() :: keyword()
    def project do
      [
        app: :sigil_guard_sbom_fixture,
        version: "1.0.0",
        source_url: "https://example.invalid/sigil_guard_sbom_fixture",
        package: [
          name: "sigil_guard_sbom_fixture",
          licenses: ["MIT"]
        ],
        deps: [
          {:remote_runtime, "~> 0.1", github: "example/remote_runtime"}
        ]
      ]
    end
  end

  defmodule BadDependencyShapeProject do
    @moduledoc false

    @spec project() :: keyword()
    def project do
      [
        app: :sigil_guard_sbom_fixture,
        version: "1.0.0",
        source_url: "https://example.invalid/sigil_guard_sbom_fixture",
        package: [
          name: "sigil_guard_sbom_fixture",
          licenses: ["MIT"]
        ],
        deps: [:not_a_tuple]
      ]
    end
  end

  defmodule BadDependencyOptionsProject do
    @moduledoc false

    @spec project() :: keyword()
    def project do
      [
        app: :sigil_guard_sbom_fixture,
        version: "1.0.0",
        source_url: "https://example.invalid/sigil_guard_sbom_fixture",
        package: [
          name: "sigil_guard_sbom_fixture",
          licenses: ["MIT"]
        ],
        deps: [
          {:bad_options, [:not_keyword]}
        ]
      ]
    end
  end

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

      refute MapSet.member?(package_names, "finch")
      refute MapSet.member?(package_names, "mint")
      refute MapSet.member?(package_names, "credo")
      refute MapSet.member?(package_names, "benchee")

      assert direct_dependency_ids(sbom) ==
               MapSet.new([
                 "SPDXRef-Package-jason",
                 "SPDXRef-Package-nimble-options",
                 "SPDXRef-Package-telemetry"
               ])
    end

    test "excludes non-runtime two-tuple keyword dependencies" do
      with_project(TwoTupleKeywordProject, fn ->
        sbom = Sbom.generate(created_at: @created_at)
        package_names = MapSet.new(sbom["packages"], & &1["name"])

        assert MapSet.member?(package_names, "jason")
        refute MapSet.member?(package_names, "credo")
        assert :ok = Sbom.verify_document(sbom)
      end)
    end

    test "rejects runtime dependencies missing from the lockfile" do
      with_project(MissingRuntimeLockProject, fn ->
        assert_raise Mix.Error, ~r/missing_runtime_dependency_lock.*not_locked/, fn ->
          Sbom.generate(created_at: @created_at)
        end

        assert {:error, {:missing_runtime_dependency_lock, :not_locked}} =
                 Sbom.verify_document(%{})
      end)
    end

    test "rejects runtime non-Hex dependency sources" do
      with_project(RuntimePathProject, fn ->
        assert_raise Mix.Error, ~r/unsupported_runtime_dependency.*local_runtime/, fn ->
          Sbom.generate(created_at: @created_at)
        end

        assert {:error, {:unsupported_runtime_dependency, :local_runtime}} =
                 Sbom.verify_document(%{})
      end)
    end

    test "rejects runtime git dependency sources" do
      with_project(RuntimeGithubProject, fn ->
        assert_raise Mix.Error, ~r/unsupported_runtime_dependency.*remote_runtime/, fn ->
          Sbom.generate(created_at: @created_at)
        end

        assert {:error, {:unsupported_runtime_dependency, :remote_runtime}} =
                 Sbom.verify_document(%{})
      end)
    end

    test "rejects invalid dependency shapes" do
      with_project(BadDependencyShapeProject, fn ->
        assert_raise Mix.Error, ~r/invalid_dependency/, fn ->
          Sbom.generate(created_at: @created_at)
        end

        assert {:error, :invalid_dependency} = Sbom.verify_document(%{})
      end)
    end

    test "rejects dependency tuples with invalid option lists" do
      with_project(BadDependencyOptionsProject, fn ->
        assert_raise Mix.Error, ~r/unsupported_runtime_dependency.*bad_options/, fn ->
          Sbom.generate(created_at: @created_at)
        end

        assert {:error, {:unsupported_runtime_dependency, :bad_options}} =
                 Sbom.verify_document(%{})
      end)
    end

    test "allows non-runtime non-Hex dependency sources" do
      with_project(NonRuntimePathProject, fn ->
        sbom = Sbom.generate(created_at: @created_at)
        package_names = MapSet.new(sbom["packages"], & &1["name"])

        assert MapSet.member?(package_names, "jason")
        refute MapSet.member?(package_names, "local_dev")
        assert :ok = Sbom.verify_document(sbom)
      end)
    end
  end

  describe "verify_document/1" do
    test "accepts the generated SPDX document shape for the current project" do
      sbom = verifiable_sbom()

      assert :ok = Sbom.verify_document(sbom)
    end

    test "rejects non-map documents" do
      assert {:error, :invalid_document} = Sbom.verify_document([])
    end

    test "rejects invalid SPDX metadata" do
      sbom =
        verifiable_sbom()
        |> Map.put("spdxVersion", "SPDX-2.2")

      assert {:error, :invalid_spdx_version} = Sbom.verify_document(sbom)

      assert {:error, :invalid_document_name} =
               verifiable_sbom()
               |> Map.put("name", "tampered")
               |> Sbom.verify_document()

      assert {:error, :invalid_document_namespace} =
               verifiable_sbom()
               |> Map.put("documentNamespace", "https://example.invalid/sbom/tampered")
               |> Sbom.verify_document()

      assert {:error, :invalid_document_namespace} =
               verifiable_sbom()
               |> Map.update!("documentNamespace", fn namespace ->
                 Regex.replace(~r/[a-f0-9]{64}\z/, namespace, String.duplicate("b", 64))
               end)
               |> Sbom.verify_document()

      assert {:error, :invalid_creation_info} =
               verifiable_sbom()
               |> put_in(["creationInfo", "created"], "not-a-timestamp")
               |> Sbom.verify_document()
    end

    test "rejects documents without the expected root package" do
      sbom =
        verifiable_sbom()
        |> Map.put("packages", [])

      assert {:error, :missing_root_package} = Sbom.verify_document(sbom)
    end

    test "rejects tampered root package metadata" do
      for {field, value} <- [
            {"downloadLocation", "https://evil.example/source"},
            {"licenseDeclared", "NOASSERTION"},
            {"licenseConcluded", "NOASSERTION"},
            {"supplier", "Organization: Other"},
            {"filesAnalyzed", true}
          ] do
        sbom =
          verifiable_sbom()
          |> update_root_package(field, value)

        assert {:error, :invalid_root_package} = Sbom.verify_document(sbom),
               "expected invalid root package after tampering #{field}"
      end
    end

    test "rejects documents without the root DESCRIBES relationship" do
      sbom =
        verifiable_sbom()
        |> Map.put("relationships", [])

      assert {:error, :missing_describes_relationship} = Sbom.verify_document(sbom)
    end

    test "rejects tampered dependency packages" do
      sbom =
        verifiable_sbom()
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
        verifiable_sbom()
        |> update_in(["packages"], fn packages ->
          Enum.reject(packages, &(&1["name"] == "jason"))
        end)

      assert {:error, :missing_dependency_package} = Sbom.verify_document(sbom)
    end

    test "rejects unexpected packages" do
      sbom =
        verifiable_sbom()
        |> update_in(["packages"], fn packages ->
          [
            %{
              "name" => "shadow",
              "SPDXID" => "SPDXRef-Package-shadow",
              "versionInfo" => "9.9.9"
            }
            | packages
          ]
        end)

      assert {:error, :unexpected_package} = Sbom.verify_document(sbom)
    end

    test "rejects missing dependency relationships" do
      sbom =
        verifiable_sbom()
        |> update_in(["relationships"], fn relationships ->
          Enum.reject(relationships, fn relationship ->
            relationship["spdxElementId"] == "SPDXRef-Package-sigil-guard" and
              relationship["relationshipType"] == "DEPENDS_ON" and
              relationship["relatedSpdxElement"] == "SPDXRef-Package-jason"
          end)
        end)

      assert {:error, :missing_dependency_relationship} = Sbom.verify_document(sbom)
    end

    test "rejects unexpected relationships" do
      sbom =
        verifiable_sbom()
        |> update_in(["relationships"], fn relationships ->
          [
            %{
              "spdxElementId" => "SPDXRef-Package-sigil-guard",
              "relationshipType" => "DEPENDS_ON",
              "relatedSpdxElement" => "SPDXRef-Package-shadow"
            }
            | relationships
          ]
        end)

      assert {:error, :unexpected_relationship} = Sbom.verify_document(sbom)
    end
  end

  describe "verify_file/1" do
    test "accepts valid JSON SPDX files" do
      output = tmp_path("valid")
      sbom = verifiable_sbom()

      File.write!(output, Jason.encode!(sbom))

      assert :ok = Sbom.verify_file(output)
    end

    test "rejects invalid JSON and missing files" do
      output = tmp_path("invalid")

      File.write!(output, "{")

      assert {:error, :invalid_json} = Sbom.verify_file(output)
      assert {:error, :enoent} = Sbom.verify_file(tmp_path("missing"))
      assert {:error, :invalid_path} = Sbom.verify_file(:not_a_path)
    end
  end

  describe "verify_file/2 (SHA-256 digest verification)" do
    test "accepts a file whose digest matches the expected value" do
      output = tmp_path("digest-ok")
      body = Jason.encode!(verifiable_sbom())
      File.write!(output, body)
      sha256 = Base.encode16(:crypto.hash(:sha256, body), case: :lower)

      assert :ok = Sbom.verify_file(output, sha256)
      # The expected digest is compared case-insensitively.
      assert :ok = Sbom.verify_file(output, String.upcase(sha256))
    end

    test "fails :sbom_digest_mismatch on digest drift, before structural checks" do
      output = tmp_path("digest-drift")
      File.write!(output, Jason.encode!(verifiable_sbom()))

      assert {:error, :sbom_digest_mismatch} =
               Sbom.verify_file(output, String.duplicate("0", 64))
    end

    test "rejects malformed inputs" do
      assert {:error, :invalid_path} = Sbom.verify_file(:not_a_path, "abc")

      assert {:error, :enoent} =
               Sbom.verify_file(tmp_path("missing"), String.duplicate("0", 64))
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

    test "raises for invalid CLI options" do
      assert_raise Mix.Error, ~r/invalid options/, fn ->
        Sbom.run(["--unknown"])
      end
    end

    test "raises for invalid SBOM files" do
      output = tmp_path("verify-invalid")
      File.write!(output, Jason.encode!(%{}))

      assert_raise Mix.Error, ~r/invalid SBOM: :invalid_spdx_version/, fn ->
        Sbom.run(["--verify", output])
      end
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

  defp verifiable_sbom do
    Sbom.generate(created_at: @created_at)
  end

  defp update_root_package(sbom, field, value) do
    update_in(sbom, ["packages"], fn packages ->
      Enum.map(packages, fn
        %{"name" => "sigil_guard"} = package -> Map.put(package, field, value)
        package -> package
      end)
    end)
  end

  defp with_project(project, fun) do
    Mix.Project.push(project)

    try do
      fun.()
    after
      Mix.Project.pop()
    end
  end

  defp tmp_path(label) do
    path =
      System.tmp_dir!()
      |> Path.join("sigil_guard_sbom_test_#{label}_#{System.unique_integer()}.json")

    on_exit(fn -> File.rm(path) end)
    path
  end
end
