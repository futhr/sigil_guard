defmodule SigilGuard.ConfigTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Config

  setup do
    original_patterns = Application.get_env(:sigil_guard, :scanner_patterns)
    original_backend = Application.get_env(:sigil_guard, :backend)
    original_profile = Application.get_env(:sigil_guard, :protocol_profile)
    original_url = Application.get_env(:sigil_guard, :registry_url)
    original_ttl = Application.get_env(:sigil_guard, :registry_ttl_ms)
    original_timeout = Application.get_env(:sigil_guard, :registry_timeout_ms)
    original_retry = Application.get_env(:sigil_guard, :registry_retry_ms)
    original_enabled = Application.get_env(:sigil_guard, :registry_enabled)
    original_require_signed = Application.get_env(:sigil_guard, :registry_require_signed_bundles)
    original_bundle_keys = Application.get_env(:sigil_guard, :registry_bundle_public_keys)

    original_bundle_max_age =
      Application.get_env(:sigil_guard, :registry_bundle_max_age_seconds)

    original_bundle_clock_skew =
      Application.get_env(:sigil_guard, :registry_bundle_clock_skew_seconds)

    on_exit(fn ->
      if original_patterns,
        do: Application.put_env(:sigil_guard, :scanner_patterns, original_patterns),
        else: Application.delete_env(:sigil_guard, :scanner_patterns)

      if original_backend,
        do: Application.put_env(:sigil_guard, :backend, original_backend),
        else: Application.delete_env(:sigil_guard, :backend)

      if original_profile,
        do: Application.put_env(:sigil_guard, :protocol_profile, original_profile),
        else: Application.delete_env(:sigil_guard, :protocol_profile)

      if original_url,
        do: Application.put_env(:sigil_guard, :registry_url, original_url),
        else: Application.delete_env(:sigil_guard, :registry_url)

      if original_ttl,
        do: Application.put_env(:sigil_guard, :registry_ttl_ms, original_ttl),
        else: Application.delete_env(:sigil_guard, :registry_ttl_ms)

      if original_timeout,
        do: Application.put_env(:sigil_guard, :registry_timeout_ms, original_timeout),
        else: Application.delete_env(:sigil_guard, :registry_timeout_ms)

      if original_retry,
        do: Application.put_env(:sigil_guard, :registry_retry_ms, original_retry),
        else: Application.delete_env(:sigil_guard, :registry_retry_ms)

      if original_enabled,
        do: Application.put_env(:sigil_guard, :registry_enabled, original_enabled),
        else: Application.delete_env(:sigil_guard, :registry_enabled)

      if original_require_signed,
        do:
          Application.put_env(
            :sigil_guard,
            :registry_require_signed_bundles,
            original_require_signed
          ),
        else: Application.delete_env(:sigil_guard, :registry_require_signed_bundles)

      if original_bundle_keys,
        do: Application.put_env(:sigil_guard, :registry_bundle_public_keys, original_bundle_keys),
        else: Application.delete_env(:sigil_guard, :registry_bundle_public_keys)

      if is_nil(original_bundle_max_age),
        do: Application.delete_env(:sigil_guard, :registry_bundle_max_age_seconds),
        else:
          Application.put_env(
            :sigil_guard,
            :registry_bundle_max_age_seconds,
            original_bundle_max_age
          )

      if is_nil(original_bundle_clock_skew),
        do: Application.delete_env(:sigil_guard, :registry_bundle_clock_skew_seconds),
        else:
          Application.put_env(
            :sigil_guard,
            :registry_bundle_clock_skew_seconds,
            original_bundle_clock_skew
          )
    end)

    :ok
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
end
