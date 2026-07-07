defmodule SigilGuard.ConfigTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Config
  alias SigilGuard.ConfigError

  @env_keys [
    :scanner_patterns,
    :backend,
    :protocol_profile,
    :registry_url,
    :registry_ttl_ms,
    :registry_timeout_ms,
    :registry_retry_ms,
    :registry_enabled,
    :registry_require_signed_bundles,
    :registry_bundle_public_keys,
    :registry_bundle_max_age_seconds,
    :registry_bundle_clock_skew_seconds,
    :trust_bundle,
    :http_client,
    :attestation_ttl_ms,
    :max_skew_ms,
    :replay_ttl_ms,
    :vault_master_key,
    :trust_mappings
  ]
  @removed_keys [
    :backend,
    :protocol_profile,
    :registry_url,
    :registry_ttl_ms,
    :registry_timeout_ms,
    :registry_retry_ms,
    :registry_enabled,
    :registry_require_signed_bundles,
    :registry_bundle_public_keys,
    :registry_bundle_max_age_seconds,
    :registry_bundle_clock_skew_seconds
  ]

  setup do
    original = Map.new(@env_keys, &{&1, Application.fetch_env(:sigil_guard, &1)})

    on_exit(fn ->
      Enum.each(original, fn
        {key, {:ok, value}} -> Application.put_env(:sigil_guard, key, value)
        {key, :error} -> Application.delete_env(:sigil_guard, key)
      end)
    end)

    :ok
  end

  describe "validate!/1" do
    test "validates the v3 closed configuration surface through NimbleOptions" do
      validated = Config.validate!([])

      assert Keyword.fetch!(validated, :trust_bundle) == :none
      assert Keyword.fetch!(validated, :scanner_patterns) == :built_in
      assert Keyword.fetch!(validated, :http_client) == nil
      assert Keyword.fetch!(validated, :attestation_ttl_ms) == 300_000
      assert Keyword.fetch!(validated, :max_skew_ms) == 60_000
      assert Keyword.fetch!(validated, :replay_ttl_ms) == 300_000
      assert Keyword.fetch!(validated, :vault_master_key) == nil
    end

    test "accepts configured v3 values" do
      opts = [
        trust_bundle: {:file, "priv/sigil_guard/trust_bundle.json"},
        scanner_patterns: :bundle,
        http_client: SigilGuard.TestHTTPClient,
        attestation_ttl_ms: 60_000,
        max_skew_ms: 0,
        replay_ttl_ms: 120_000,
        vault_master_key: Base.encode64(:crypto.strong_rand_bytes(32)),
        trust_mappings: [{"spiffe://prod/*", :high}, {"user:42", :medium}]
      ]

      assert Config.validate!(opts) == opts
    end

    test "rejects removed trust bundle source constructors" do
      assert_raise ConfigError, ~r/:trust_bundle.*invalid_config.*MIGRATING-3\.0\.md/, fn ->
        Config.validate!(trust_bundle: {:path, "priv/sigil_guard/trust_bundle.json"})
      end
    end

    test "raises typed errors for unknown keys" do
      assert_raise ConfigError, ~r/:unknown.*unknown_config_key.*MIGRATING-3\.0\.md/, fn ->
        Config.validate!(unknown: true)
      end
    end

    test "raises typed errors for removed keys" do
      assert_raise ConfigError,
                   ~r/:registry_url.*legacy_contract_removed.*MIGRATING-3\.0\.md/,
                   fn ->
                     Config.validate!(registry_url: "https://custom.example.com")
                   end
    end

    test "raises typed errors for removed values" do
      assert_raise ConfigError,
                   ~r/:scanner_patterns.*legacy_contract_removed.*MIGRATING-3\.0\.md/,
                   fn ->
                     Config.validate!(scanner_patterns: :registry)
                   end
    end

    test "raises typed errors for bad value types" do
      error =
        assert_raise ConfigError, fn ->
          Config.validate!(vault_master_key: 123)
        end

      assert error.key == :vault_master_key
      assert error.reason == :invalid_config
      assert error.message =~ "MIGRATING-3.0.md"
    end

    test "raises typed errors for out-of-range values" do
      assert_raise ConfigError,
                   ~r/:attestation_ttl_ms.*invalid_config.*MIGRATING-3\.0\.md/,
                   fn ->
                     Config.validate!(attestation_ttl_ms: 0)
                   end
    end

    test "raises typed errors for invalid trust bundle sources" do
      assert_raise ConfigError, ~r/:trust_bundle.*invalid_config.*MIGRATING-3\.0\.md/, fn ->
        Config.validate!(trust_bundle: 123)
      end
    end

    test "raises typed errors for invalid cross-option combinations" do
      assert_raise ConfigError,
                   ~r/:scanner_patterns.*invalid_config.*MIGRATING-3\.0\.md/,
                   fn ->
                     Config.validate!(scanner_patterns: :bundle)
                   end
    end

    test "raises typed errors for non-keyword config" do
      assert_raise ConfigError, ~r/:sigil_guard.*invalid_config.*MIGRATING-3\.0\.md/, fn ->
        Config.validate!(:bad)
      end
    end

    test "generates schema documentation" do
      docs = Config.schema_docs()

      assert docs =~ ":attestation_ttl_ms"
      assert docs =~ ":scanner_patterns"
    end
  end

  describe "validate!/0" do
    test "validates application environment" do
      clear_v3_config()
      Application.put_env(:sigil_guard, :attestation_ttl_ms, 30_000)

      assert Keyword.fetch!(Config.validate!(), :attestation_ttl_ms) == 30_000
    end
  end

  describe "removed-key boot matrix" do
    test "each removed key fails application boot with a migration pointer" do
      for key <- @removed_keys do
        clear_v3_config()
        Application.put_env(:sigil_guard, key, removed_key_value(key))

        error =
          assert_raise ConfigError, fn ->
            SigilGuard.Application.start(:normal, [])
          end

        assert error.key == key
        assert error.reason == :legacy_contract_removed
        assert error.message =~ Atom.to_string(key)
        assert error.message =~ "MIGRATING-3.0.md"
      end
    end

    test "legacy scanner_patterns registry value fails application boot" do
      clear_v3_config()
      Application.put_env(:sigil_guard, :scanner_patterns, :registry)

      error =
        assert_raise ConfigError, fn ->
          SigilGuard.Application.start(:normal, [])
        end

      assert error.key == :scanner_patterns
      assert error.reason == :legacy_contract_removed
      assert error.message =~ "scanner_patterns"
      assert error.message =~ "MIGRATING-3.0.md"
    end
  end

  describe "removed v2 accessors" do
    test "legacy config readers are not exported" do
      removed = [
        {:backend, 0},
        {:protocol_profile, 0},
        {:registry_url, 0},
        {:registry_ttl_ms, 0},
        {:registry_timeout_ms, 0},
        {:registry_retry_ms, 0},
        {:registry_enabled?, 0},
        {:registry_require_signed_bundles?, 0},
        {:registry_bundle_public_keys, 0},
        {:registry_bundle_max_age_seconds, 0},
        {:registry_bundle_clock_skew_seconds, 0}
      ]

      for {function, arity} <- removed do
        refute function_exported?(Config, function, arity)
      end
    end
  end

  describe "scanner_patterns/0" do
    test "defaults to :built_in" do
      Application.delete_env(:sigil_guard, :scanner_patterns)
      assert Config.scanner_patterns() == :built_in
    end

    test "returns configured scanner patterns source" do
      Application.put_env(:sigil_guard, :scanner_patterns, :bundle)
      assert Config.scanner_patterns() == :bundle
    end
  end

  describe "trust_mappings validation (SP.10)" do
    test "accepts exact patterns, a single trailing wildcard, and an empty table" do
      for mappings <- [[], [{"user:42", :high}], [{"spiffe://prod/*", :medium}, {"*", :low}]] do
        assert Config.validate!(trust_mappings: mappings)[:trust_mappings] == mappings
      end
    end

    test "rejects a non-list, non-tuple entry, or non-string pattern" do
      for bad <- [:nope, ["not-a-tuple"], [{123, :high}], [{"a", :high, :extra}]] do
        assert_raise ConfigError, ~r/:trust_mappings/, fn ->
          Config.validate!(trust_mappings: bad)
        end
      end
    end

    test "rejects wildcards outside a single trailing position" do
      for bad <- [[{"a*b", :high}], [{"a*b*", :high}], [{"**", :high}], [{"*x", :high}]] do
        assert_raise ConfigError, ~r/:trust_mappings/, fn ->
          Config.validate!(trust_mappings: bad)
        end
      end
    end

    test "rejects a trust level outside the closed set" do
      assert_raise ConfigError, ~r/:trust_mappings/, fn ->
        Config.validate!(trust_mappings: [{"user:*", :godmode}])
      end
    end
  end

  defp clear_v3_config do
    for key <- @env_keys do
      Application.delete_env(:sigil_guard, key)
    end
  end

  defp removed_key_value(:backend), do: :elixir
  defp removed_key_value(:protocol_profile), do: :auto
  defp removed_key_value(:registry_url), do: "https://registry.example"
  defp removed_key_value(:registry_ttl_ms), do: 60_000
  defp removed_key_value(:registry_timeout_ms), do: 5_000
  defp removed_key_value(:registry_retry_ms), do: 1_000
  defp removed_key_value(:registry_enabled), do: true
  defp removed_key_value(:registry_require_signed_bundles), do: true
  defp removed_key_value(:registry_bundle_public_keys), do: %{}
  defp removed_key_value(:registry_bundle_max_age_seconds), do: 60
  defp removed_key_value(:registry_bundle_clock_skew_seconds), do: 60
end
