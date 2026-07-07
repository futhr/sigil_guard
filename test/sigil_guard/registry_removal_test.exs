defmodule SigilGuard.RegistryRemovalTest do
  use ExUnit.Case, async: true

  @registry_module SigilGuard.Registry
  @bundle_module SigilGuard.Registry.Bundle
  @registry_functions [
    {:fetch_bundle, []},
    {:resolve_did, ["did:example:alice"]},
    {:resolve_key, ["did:example:alice"]},
    {:fetch_policies, []}
  ]
  @bundle_functions [
    {:canonical_bytes, [%{}]},
    {:digest, [%{}]},
    {:sign, [%{}, SigilGuard.TestSigner]},
    {:verify, [%{}]}
  ]

  describe "v3 registry adapter removal" do
    test "SigilGuard.Registry is deleted, not hidden" do
      refute Code.ensure_loaded?(@registry_module)
    end

    test "removed public calls raise UndefinedFunctionError cleanly" do
      for {function, args} <- @registry_functions do
        assert_raise UndefinedFunctionError, fn ->
          apply(@registry_module, function, args)
        end
      end
    end
  end

  describe "v3 registry bundle removal" do
    test "SigilGuard.Registry.Bundle is deleted, not hidden" do
      refute Code.ensure_loaded?(@bundle_module)
    end

    test "removed bundle calls raise UndefinedFunctionError cleanly" do
      for {function, args} <- @bundle_functions do
        assert_raise UndefinedFunctionError, fn ->
          apply(@bundle_module, function, args)
        end
      end
    end

    test "legacy bundle fixture remains parseable as historical data" do
      fixture =
        "test/fixtures/historical/legacy_registry_bundle.json"
        |> File.read!()
        |> Jason.decode!()

      assert fixture["generated_at"] == "2026-06-30T12:00:00Z"
      assert [%{"name" => "registry_pat", "regex" => "REG_[0-9]+"}] = fixture["patterns"]
      assert fixture["provenance"]["issuer"] == "did:sigil:registry"
      assert fixture["provenance"]["algorithm"] == "Ed25519"
    end
  end
end
