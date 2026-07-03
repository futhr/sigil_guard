defmodule SigilGuard.CapabilityManifestTest do
  use ExUnit.Case, async: true

  alias SigilGuard.Canonical.JCS
  alias SigilGuard.CapabilityManifest

  @fixture Path.expand("../fixtures/capability_manifest/repo_file_write", __DIR__)

  describe "new/1" do
    test "validates the repo_file_write canonical manifest" do
      manifest = read_json("manifest.json")

      assert {:ok, capability} = CapabilityManifest.new(manifest)

      assert capability.name == "repo_file_write"
      assert capability.manifest_format == "sigil_guard_capability_manifest/v1"
      assert capability.side_effects == ["write"]
      assert capability.sandbox == %{"min_isolation" => "container", "required" => true}
      assert capability.preimage == read_json("preimage.json")
      assert capability.digest == read_json("expected.json")["manifest_digest"]
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
         Map.put(manifest(), "manifest_format", "sigil_guard_capability_manifest/v2")},
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
        |> Map.put("description_sha256", read_json("expected.json")["description_sha256"])
        |> Map.put("input_schema_sha256", read_json("expected.json")["input_schema_sha256"])
        |> Map.put("annotations_sha256", read_json("expected.json")["annotations_sha256"])

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
  end

  describe "digest/1" do
    test "reproduces committed golden vectors and the SP.01 tool_request digest" do
      manifest_json = read_fixture_bytes("manifest.json")
      preimage_json = read_fixture_bytes("preimage.json")
      expected = read_json("expected.json")
      tool_request = read_json(["agent_trust", "tool_request", "expected.json"])

      assert {:ok, ^manifest_json} = JCS.encode(manifest())
      assert {:ok, capability} = CapabilityManifest.new(manifest())
      assert {:ok, ^preimage_json} = JCS.encode(capability.preimage)
      assert CapabilityManifest.digest(capability) == {:ok, expected["manifest_digest"]}
      assert CapabilityManifest.digest(manifest()) == {:ok, expected["manifest_digest"]}
      assert tool_request["manifest_digest"] == expected["manifest_digest"]
    end

    test "can digest a struct from its preimage when no cached digest is set" do
      manifest = %CapabilityManifest{digest: nil, preimage: read_json("preimage.json")}

      assert CapabilityManifest.digest(manifest) ==
               {:ok, read_json("expected.json")["manifest_digest"]}
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

  defp manifest, do: read_json("manifest.json")

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
    [Path.expand("../fixtures", __DIR__) | path]
    |> Path.join()
    |> File.read!()
    |> Jason.decode!()
  end
end
