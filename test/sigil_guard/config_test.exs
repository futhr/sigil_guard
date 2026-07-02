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
    :vault_master_key
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
        trust_bundle: {:path, "priv/sigil_guard/trust_bundle.json"},
        scanner_patterns: :bundle,
        http_client: SigilGuard.TestHTTPClient,
        attestation_ttl_ms: 60_000,
        max_skew_ms: 0,
        replay_ttl_ms: 120_000,
        vault_master_key: Base.encode64(:crypto.strong_rand_bytes(32))
      ]

      assert Config.validate!(opts) == opts
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

  describe "backend/0" do
    test "defaults to :elixir" do
      Application.delete_env(:sigil_guard, :backend)
      assert Config.backend() == :elixir
    end

    test "returns configured backend" do
      Application.put_env(:sigil_guard, :backend, SigilGuard.Backend.Elixir)
      assert Config.backend() == SigilGuard.Backend.Elixir
    end
  end

  describe "protocol_profile/0" do
    test "defaults to :auto" do
      Application.delete_env(:sigil_guard, :protocol_profile)
      assert Config.protocol_profile() == :auto
    end

    test "returns configured profile" do
      Application.put_env(:sigil_guard, :protocol_profile, :sigil_reference_0_1)
      assert Config.protocol_profile() == :sigil_reference_0_1
    end

    test "raises for invalid profile" do
      Application.put_env(:sigil_guard, :protocol_profile, :bogus)

      assert_raise ArgumentError, ~r/invalid :sigil_guard protocol_profile/, fn ->
        Config.protocol_profile()
      end
    end
  end

  describe "scanner_patterns/0" do
    test "defaults to :built_in" do
      Application.delete_env(:sigil_guard, :scanner_patterns)
      assert Config.scanner_patterns() == :built_in
    end

    test "returns configured scanner patterns source" do
      Application.put_env(:sigil_guard, :scanner_patterns, :registry)
      assert Config.scanner_patterns() == :registry
    end
  end

  describe "registry_url/0" do
    test "defaults to nil" do
      Application.delete_env(:sigil_guard, :registry_url)
      assert Config.registry_url() == nil
    end

    test "returns configured URL" do
      Application.put_env(:sigil_guard, :registry_url, "https://custom.example.com")
      assert Config.registry_url() == "https://custom.example.com"
    end
  end

  describe "registry_ttl_ms/0" do
    test "returns default TTL (1 hour)" do
      Application.delete_env(:sigil_guard, :registry_ttl_ms)
      assert Config.registry_ttl_ms() == :timer.hours(1)
    end

    test "returns configured TTL" do
      Application.put_env(:sigil_guard, :registry_ttl_ms, 30_000)
      assert Config.registry_ttl_ms() == 30_000
    end
  end

  describe "registry_timeout_ms/0" do
    test "returns default timeout (5 seconds)" do
      Application.delete_env(:sigil_guard, :registry_timeout_ms)
      assert Config.registry_timeout_ms() == 5_000
    end

    test "returns configured timeout" do
      Application.put_env(:sigil_guard, :registry_timeout_ms, 10_000)
      assert Config.registry_timeout_ms() == 10_000
    end
  end

  describe "registry_retry_ms/0" do
    test "returns default retry interval (1 minute)" do
      Application.delete_env(:sigil_guard, :registry_retry_ms)
      assert Config.registry_retry_ms() == :timer.minutes(1)
    end

    test "returns configured retry interval" do
      Application.put_env(:sigil_guard, :registry_retry_ms, 15_000)
      assert Config.registry_retry_ms() == 15_000
    end
  end

  describe "registry_enabled?/0" do
    test "defaults to false" do
      Application.delete_env(:sigil_guard, :registry_enabled)
      refute Config.registry_enabled?()
    end

    test "returns configured value" do
      Application.put_env(:sigil_guard, :registry_enabled, true)
      assert Config.registry_enabled?()
    end
  end

  describe "registry_require_signed_bundles?/0" do
    test "defaults to false" do
      Application.delete_env(:sigil_guard, :registry_require_signed_bundles)
      refute Config.registry_require_signed_bundles?()
    end

    test "returns configured value" do
      Application.put_env(:sigil_guard, :registry_require_signed_bundles, true)
      assert Config.registry_require_signed_bundles?()
    end
  end

  describe "registry_bundle_public_keys/0" do
    test "defaults to empty map" do
      Application.delete_env(:sigil_guard, :registry_bundle_public_keys)
      assert Config.registry_bundle_public_keys() == %{}
    end

    test "returns configured issuer keys" do
      keys = %{"did:sigil:registry" => "pub"}
      Application.put_env(:sigil_guard, :registry_bundle_public_keys, keys)
      assert Config.registry_bundle_public_keys() == keys
    end
  end

  describe "registry_bundle_max_age_seconds/0" do
    test "defaults to nil" do
      Application.delete_env(:sigil_guard, :registry_bundle_max_age_seconds)
      assert Config.registry_bundle_max_age_seconds() == nil
    end

    test "returns configured maximum bundle age" do
      Application.put_env(:sigil_guard, :registry_bundle_max_age_seconds, 86_400)
      assert Config.registry_bundle_max_age_seconds() == 86_400
    end
  end

  describe "registry_bundle_clock_skew_seconds/0" do
    test "defaults to 60 seconds" do
      Application.delete_env(:sigil_guard, :registry_bundle_clock_skew_seconds)
      assert Config.registry_bundle_clock_skew_seconds() == 60
    end

    test "returns configured clock skew" do
      Application.put_env(:sigil_guard, :registry_bundle_clock_skew_seconds, 10)
      assert Config.registry_bundle_clock_skew_seconds() == 10
    end
  end

  defp clear_v3_config do
    for key <- @env_keys do
      Application.delete_env(:sigil_guard, key)
    end
  end
end
