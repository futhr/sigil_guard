defmodule SigilGuard.RegistryRemovalTest do
  @moduledoc false

  use ExUnit.Case, async: true

  @registry_module SigilGuard.Registry
  @bundle_module SigilGuard.Registry.Bundle
  @cache_module SigilGuard.Registry.Cache
  @profile_module SigilGuard.Profile
  @envelope_module SigilGuard.Envelope
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
  @cache_functions [
    {:status, []},
    {:patterns, []},
    {:rule_count, []},
    {:source, []},
    {:refresh, []}
  ]
  @profile_functions [
    {:profiles, []},
    {:normalize!, [:auto]},
    {:wire_verdict_format, [:auto]},
    {:verdict_acceptance, [:auto]},
    {:require_blocked_reason_on_verify?, [:auto]},
    {:registry_identity_endpoints, [:auto]}
  ]
  @envelope_functions [
    {:canonical_bytes, ["did:example:agent", :allowed, "2026-01-01T00:00:00.000Z", "00"]},
    {:sign, ["did:example:agent", :allowed, [signer: SigilGuard.TestSigner]]},
    {:verify, [%{}, SigilGuard.TestSigner.public_key_b64u()]},
    {:generate_timestamp, []},
    {:generate_nonce, []}
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

  describe "historical legacy envelope/profile vectors" do
    test "legacy envelope golden vectors remain parseable as historical data" do
      fixture =
        "test/fixtures/historical/envelope_golden_vectors.sigil_protocol_0_1_5.json"
        |> File.read!()
        |> Jason.decode!()

      assert fixture["schema"] == "sigil_guard.envelope_golden_vectors.v1"
      assert fixture["generated_by"]["crate_version"] == "0.1.5"

      assert Enum.map(fixture["vectors"], & &1["case"]) == [
               "rust_allowed_reference_0_1_5",
               "rust_scanned_reference_0_1_5",
               "rust_blocked_reference_0_1_5"
             ]

      assert Enum.all?(fixture["vectors"], fn vector ->
               is_map(vector["envelope"]) and is_binary(vector["canonical_json"])
             end)
    end

    test "runtime library code does not read historical fixture paths" do
      matches =
        "lib/sigil_guard"
        |> Path.join("**/*.{ex,exs}")
        |> Path.wildcard()
        |> Enum.filter(fn path ->
          path
          |> File.read!()
          |> String.contains?("test/fixtures/historical")
        end)

      assert matches == []
    end
  end

  describe "v3 registry cache removal" do
    test "SigilGuard.Registry.Cache is deleted, not hidden" do
      refute Code.ensure_loaded?(@cache_module)
    end

    test "removed cache calls raise UndefinedFunctionError cleanly" do
      for {function, args} <- @cache_functions do
        assert_raise UndefinedFunctionError, fn ->
          apply(@cache_module, function, args)
        end
      end
    end

    test "application boot has no registry cache or Finch children" do
      child_modules =
        SigilGuard.Supervisor
        |> Supervisor.which_children()
        |> Enum.map(fn {id, _, _, modules} -> {id, modules} end)

      refute Enum.any?(child_modules, fn {id, modules} ->
               id in [SigilGuard.Finch, @cache_module] or @cache_module in List.wrap(modules)
             end)
    end

    test "runtime source has no Finch dependency or callsite" do
      direct_deps =
        Mix.Project.config()
        |> Keyword.fetch!(:deps)
        |> Enum.map(fn
          {app, _} -> app
          {app, _, _} -> app
        end)

      refute :finch in direct_deps

      runtime_finch_references =
        "lib/sigil_guard/**/*.ex"
        |> Path.wildcard()
        |> Enum.filter(fn path ->
          source = File.read!(path)
          String.contains?(source, "Finch.") or String.contains?(source, "SigilGuard.Finch")
        end)

      assert runtime_finch_references == []
    end
  end

  describe "v3 legacy profile removal" do
    test "SigilGuard.Profile is deleted, not hidden" do
      refute Code.ensure_loaded?(@profile_module)
    end

    test "removed profile calls raise UndefinedFunctionError cleanly" do
      for {function, args} <- @profile_functions do
        assert_raise UndefinedFunctionError, fn ->
          apply(@profile_module, function, args)
        end
      end
    end
  end

  describe "v3 legacy envelope removal" do
    test "SigilGuard.Envelope is deleted, not hidden" do
      refute Code.ensure_loaded?(@envelope_module)
    end

    test "removed envelope calls raise UndefinedFunctionError cleanly" do
      for {function, args} <- @envelope_functions do
        assert_raise UndefinedFunctionError, fn ->
          apply(@envelope_module, function, args)
        end
      end
    end
  end
end
