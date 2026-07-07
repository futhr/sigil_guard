defmodule SigilGuard.RegistryRemovalTest do
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
