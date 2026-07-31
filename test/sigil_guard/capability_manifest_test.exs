defmodule SigilGuard.CapabilityManifestTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Canonical.JCS
  alias SigilGuard.CapabilityManifest

  @fixture SigilGuard.FixturePath.path("capability_manifest")
  @expected_fixture "repo_file_write.expected.json"
  @manifest_fixture "repo_file_write.manifest.json"
  @preimage_fixture "repo_file_write.preimage.json"

  describe "new/1" do
    test "fixture helper resolves independently of cwd" do
      File.cd!("test/sigil_guard/threat_model", fn ->
        assert %{"name" => "repo_file_write"} =
                 SigilGuard.FixturePath.read_json!(["capability_manifest", @manifest_fixture])
      end)
    end

    test "validates the repo_file_write canonical manifest" do
      manifest = read_json(@manifest_fixture)

      assert {:ok, capability} = CapabilityManifest.new(manifest)

      assert capability.name == "repo_file_write"
      assert capability.manifest_format == "sigil_guard_capability_manifest/v2"
      assert capability.side_effects == ["write"]
      assert capability.sandbox == %{"min_isolation" => "container", "required" => true}
      assert capability.preimage == read_json(@preimage_fixture)
      assert capability.digest == read_json(@expected_fixture)["manifest_digest"]
    end

    test "validates optional output schema and sandbox false forms" do
      output_schema = %{"properties" => %{"ok" => %{"type" => "boolean"}}, "type" => "object"}

      manifest =
        manifest()
        |> Map.delete("allowed_sink_zones")
        |> Map.delete("allowed_source_zones")
        |> Map.delete("scopes")
        |> Map.put("output_schema", output_schema)
        |> Map.put("sandbox", %{"required" => false})

      assert {:ok, capability} = CapabilityManifest.new(manifest)
      assert capability.allowed_sink_zones == nil
      assert capability.output_schema == output_schema
      assert capability.output_schema_sha256 =~ ~r/^[0-9a-f]{64}$/
      assert capability.preimage["output_schema_sha256"] == capability.output_schema_sha256
      refute Map.has_key?(capability.preimage, "output_schema")
    end

    test "rejects malformed manifest trigger classes" do
      cases = [
        {"unknown field", Map.put(manifest(), "extra", true)},
        {"missing required field", Map.delete(manifest(), "server")},
        {"bad format",
         Map.put(manifest(), "manifest_format", "sigil_guard_capability_manifest/v1")},
        {"bad enum", Map.put(manifest(), "network_access", "ambient")},
        {"unsorted list", Map.put(manifest(), "scopes", ["repo:write", "admin"])},
        {"duplicate list", Map.put(manifest(), "allowed_source_zones", ["trusted", "trusted"])},
        {"empty side effects", Map.put(manifest(), "side_effects", [])},
        {"mixed none side effect", Map.put(manifest(), "side_effects", ["none", "read"])},
        {"bad sandbox",
         Map.put(manifest(), "sandbox", %{"required" => true, "min_isolation" => "process"})},
        {"extra sandbox key",
         Map.put(manifest(), "sandbox", %{"required" => false, "min_isolation" => "container"})},
        {"non-map input schema", Map.put(manifest(), "input_schema", [])},
        {"bad issuer keyid", Map.put(manifest(), "issuer_keyid", "key")},
        {"issuer keyid with trailing newline",
         Map.put(manifest(), "issuer_keyid", manifest()["issuer_keyid"] <> "\n")},
        {"expires_at with trailing newline",
         Map.put(manifest(), "expires_at", manifest()["expires_at"] <> "\n")},
        {"regex-shaped invalid expires_at",
         Map.put(manifest(), "expires_at", "2026-99-02T12:00:00.000Z")},
        {"bad optional list", Map.put(manifest(), "audience", ["server", 1])},
        {"unsorted suspicious params",
         Map.put(manifest(), "suspicious_params", ["token", "apiKey"])},
        {"non-list suspicious params", Map.put(manifest(), "suspicious_params", %{})},
        {"unknown side effect", Map.put(manifest(), "side_effects", ["mutate"])}
      ]

      for {label, document} <- cases do
        assert CapabilityManifest.new(document) == {:error, :invalid_manifest}, label
      end

      assert CapabilityManifest.new("bad") == {:error, :invalid_manifest}

      assert CapabilityManifest.new(%{"name" => "string", name: "atom"}) ==
               {:error, :invalid_manifest}

      assert CapabilityManifest.new(Map.put(manifest(), "sandbox", "bad")) ==
               {:error, :invalid_manifest}
    end

    test "checks carried inner digests when present" do
      valid =
        manifest()
        |> Map.put("description_sha256", read_json(@expected_fixture)["description_sha256"])
        |> Map.put("input_schema_sha256", read_json(@expected_fixture)["input_schema_sha256"])
        |> Map.put("annotations_sha256", read_json(@expected_fixture)["annotations_sha256"])

      assert {:ok, %CapabilityManifest{}} = CapabilityManifest.new(valid)

      invalid = Map.put(valid, "description_sha256", String.duplicate("0", 64))

      assert CapabilityManifest.new(invalid) == {:error, :invalid_manifest}

      invalid_shape = Map.put(valid, "description_sha256", "not-a-digest")

      assert CapabilityManifest.new(invalid_shape) == {:error, :invalid_manifest}
    end

    test "rejects lying suspicious parameter disclosures" do
      lying =
        manifest()
        |> put_in(["input_schema", "required"], ["apiKey", "content", "path"])

      assert CapabilityManifest.new(lying) == {:error, :suspicious_required_param}

      disclosed = Map.put(lying, "suspicious_params", ["apiKey"])

      assert {:ok, %CapabilityManifest{suspicious_params: ["apiKey"]}} =
               CapabilityManifest.new(disclosed)
    end

    test "walks nested required lists for suspicious parameters" do
      nested_schema =
        manifest()["input_schema"]
        |> Map.put("allOf", [%{"properties" => %{}, "required" => ["session-token"]}])

      disclosed =
        manifest()
        |> Map.put("input_schema", nested_schema)
        |> Map.put("suspicious_params", ["session-token"])

      assert {:ok, %CapabilityManifest{suspicious_params: ["session-token"]}} =
               CapabilityManifest.new(disclosed)
    end

    test "returns unsupported_number_range for unsafe numeric schema values" do
      unsafe =
        manifest()
        |> put_in(["input_schema", "properties", "path", "maximum"], 9_007_199_254_740_992)

      assert CapabilityManifest.new(unsafe) == {:error, :unsupported_number_range}
    end

    test "binds MCP title, icons, and Apps UI metadata into manifest v2" do
      enriched =
        manifest()
        |> Map.put("title", "Repository writer")
        |> Map.put("icons", [
          %{
            "src" => "https://cdn.example.test/repo-write.svg",
            "mimeType" => "image/svg+xml",
            "sizes" => ["any"],
            "theme" => "light"
          }
        ])
        |> Map.put("ui", %{
          "resource_uri" => "ui://repo/review",
          "visibility" => ["app", "model"]
        })

      assert {:ok, capability} = CapabilityManifest.new(enriched)
      assert capability.title == "Repository writer"
      assert capability.title_sha256 =~ ~r/^[0-9a-f]{64}$/
      assert capability.icons_sha256 =~ ~r/^[0-9a-f]{64}$/
      assert capability.ui_sha256 =~ ~r/^[0-9a-f]{64}$/
      assert capability.preimage["title_sha256"] == capability.title_sha256
      assert capability.preimage["icons_sha256"] == capability.icons_sha256
      assert capability.preimage["ui_sha256"] == capability.ui_sha256

      changed = put_in(enriched, ["ui", "visibility"], ["app"])

      assert CapabilityManifest.verify(capability, changed) ==
               {:error, :manifest_digest_mismatch}

      data_icon =
        enriched
        |> Map.put("icons", [
          %{
            "src" => "data:image/png;base64,#{Base.encode64(<<137, 80, 78, 71>>)}",
            "mimeType" => "image/png",
            "sizes" => ["48x48"],
            "theme" => "dark"
          }
        ])

      assert {:ok, %CapabilityManifest{}} = CapabilityManifest.new(data_icon)
    end

    test "validates x-mcp-header annotations and rejects unsafe variants" do
      valid =
        manifest()
        |> put_in(
          ["input_schema", "properties", "tenant"],
          %{"type" => "string", "x-mcp-header" => "X-Tenant"}
        )

      assert {:ok, %CapabilityManifest{}} = CapabilityManifest.new(valid)

      malformed =
        put_in(
          valid,
          ["input_schema", "properties", "tenant", "x-mcp-header"],
          "X-Tenant\r\nInjected: yes"
        )

      duplicate =
        valid
        |> put_in(
          ["input_schema", "properties", "region"],
          %{"type" => "string", "x-mcp-header" => "x-tenant"}
        )

      non_primitive =
        put_in(valid, ["input_schema", "properties", "tenant", "type"], "object")

      sensitive =
        manifest()
        |> put_in(
          ["input_schema", "properties", "authorization_token"],
          %{"type" => "string", "x-mcp-header" => "Authorization"}
        )

      assert CapabilityManifest.new(malformed) == {:error, :invalid_header_annotation}
      assert CapabilityManifest.new(duplicate) == {:error, :invalid_header_annotation}
      assert CapabilityManifest.new(non_primitive) == {:error, :invalid_header_annotation}
      assert CapabilityManifest.new(sensitive) == {:error, :sensitive_header_param}

      unreachable =
        put_in(
          manifest(),
          ["input_schema", "allOf"],
          [
            %{
              "properties" => %{
                "tenant" => %{"type" => "string", "x-mcp-header" => "X-Tenant"}
              }
            }
          ]
        )

      assert CapabilityManifest.new(unreachable) == {:error, :invalid_header_annotation}
    end

    test "rejects malformed display and UI metadata" do
      assert CapabilityManifest.new(Map.put(manifest(), "title", "")) ==
               {:error, :invalid_manifest}

      assert CapabilityManifest.new(Map.put(manifest(), "icons", [%{"src" => ""}])) ==
               {:error, :invalid_manifest}

      for icon <- [
            %{"src" => "javascript:alert(1)"},
            %{"src" => "https://example.test/icon.png", "theme" => "sepia"},
            %{"src" => "https://example.test/icon.png", "sizes" => ["0x48"]},
            %{"src" => "https://example.test/icon.png", "sizes" => ["48x48", "48x48"]},
            %{"src" => "https://example.test/icon.png", "unknown" => true},
            %{"src" => "data:image/png;base64,not base64"}
          ] do
        assert CapabilityManifest.new(Map.put(manifest(), "icons", [icon])) ==
                 {:error, :invalid_manifest}
      end

      unsorted_ui =
        Map.put(manifest(), "ui", %{
          "resource_uri" => "ui://repo/review",
          "visibility" => ["model", "app"]
        })

      assert CapabilityManifest.new(unsorted_ui) == {:error, :invalid_manifest}

      empty_ui_uri =
        Map.put(manifest(), "ui", %{
          "resource_uri" => "ui://",
          "visibility" => ["app", "model"]
        })

      assert CapabilityManifest.new(empty_ui_uri) == {:error, :invalid_manifest}

      app_only_without_resource =
        Map.put(manifest(), "ui", %{"visibility" => ["app"]})

      assert {:ok, %CapabilityManifest{ui: %{"visibility" => ["app"]}}} =
               CapabilityManifest.new(app_only_without_resource)
    end
  end

  describe "digest/1" do
    test "reproduces committed golden vectors and the attestation tool_request digest" do
      manifest_json = read_fixture_bytes(@manifest_fixture)
      preimage_json = read_fixture_bytes(@preimage_fixture)
      expected = read_json(@expected_fixture)
      tool_request = read_json(["agent_trust", "tool_request", "expected.json"])

      assert {:ok, ^manifest_json} = JCS.encode(manifest())
      assert {:ok, capability} = CapabilityManifest.new(manifest())
      assert {:ok, ^preimage_json} = JCS.encode(capability.preimage)
      assert CapabilityManifest.digest(capability) == {:ok, expected["manifest_digest"]}
      assert CapabilityManifest.digest(manifest()) == {:ok, expected["manifest_digest"]}
      assert tool_request["manifest_digest"] == expected["manifest_digest"]
    end

    test "can digest a struct from its preimage when no cached digest is set" do
      manifest = %CapabilityManifest{digest: nil, preimage: read_json(@preimage_fixture)}

      assert CapabilityManifest.digest(manifest) ==
               {:ok, read_json(@expected_fixture)["manifest_digest"]}
    end

    test "fails closed for invalid digest inputs" do
      lying =
        manifest()
        |> put_in(["input_schema", "required"], ["apiKey", "content", "path"])

      unsafe =
        manifest()
        |> put_in(["input_schema", "properties", "path", "maximum"], 9_007_199_254_740_992)

      assert CapabilityManifest.digest(:bad) == {:error, :invalid_manifest}
      assert CapabilityManifest.digest(lying) == {:error, :invalid_manifest}
      assert CapabilityManifest.digest(unsafe) == {:error, :unsupported_number_range}
    end
  end

  describe "verify/2" do
    test "distinguishes schema drift from manifest drift" do
      assert {:ok, pinned} = CapabilityManifest.new(manifest())

      schema_drift =
        manifest()
        |> put_in(["input_schema", "properties", "path", "minLength"], 1)

      manifest_drift = Map.put(manifest(), "network_access", "outbound")

      assert CapabilityManifest.verify(pinned, schema_drift) == {:error, :schema_digest_mismatch}

      assert CapabilityManifest.verify(pinned, manifest_drift) ==
               {:error, :manifest_digest_mismatch}

      assert CapabilityManifest.verify(pinned, manifest()) == :ok
    end

    test "fails closed for malformed pinned or observed manifests" do
      assert {:ok, pinned} = CapabilityManifest.new(manifest())

      lying =
        manifest()
        |> put_in(["input_schema", "required"], ["apiKey", "content", "path"])

      unsafe =
        manifest()
        |> put_in(["input_schema", "properties", "path", "maximum"], 9_007_199_254_740_992)

      assert CapabilityManifest.verify(manifest(), manifest()) == :ok
      assert CapabilityManifest.verify(:bad, manifest()) == {:error, :invalid_manifest}
      assert CapabilityManifest.verify(pinned, "bad") == {:error, :invalid_manifest}
      assert CapabilityManifest.verify(pinned, unsafe) == {:error, :invalid_manifest}
      assert CapabilityManifest.verify(pinned, lying) == {:error, :suspicious_required_param}
    end
  end

  defp manifest, do: read_json(@manifest_fixture)

  defp read_fixture_bytes(file) do
    @fixture
    |> Path.join(file)
    |> File.read!()
    |> String.trim_trailing("\n")
  end

  defp read_json(file) when is_binary(file) do
    @fixture
    |> Path.join(file)
    |> File.read!()
    |> Jason.decode!()
  end

  defp read_json(path) when is_list(path) do
    SigilGuard.FixturePath.read_json!(path)
  end
end
