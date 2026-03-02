defmodule SigilGuard.ConfigTest do
  @moduledoc """
  Tests for `SigilGuard.Config`.

  Verifies that all configuration accessors return correct defaults and
  respect application environment overrides for backend selection, registry
  settings, scanner patterns, and cache TTL.
  """

  use ExUnit.Case, async: false

  alias SigilGuard.Config

  setup do
    original_patterns = Application.get_env(:sigil_guard, :scanner_patterns)
    original_backend = Application.get_env(:sigil_guard, :backend)
    original_url = Application.get_env(:sigil_guard, :registry_url)
    original_ttl = Application.get_env(:sigil_guard, :registry_ttl_ms)
    original_timeout = Application.get_env(:sigil_guard, :registry_timeout_ms)
    original_enabled = Application.get_env(:sigil_guard, :registry_enabled)

    on_exit(fn ->
      if original_patterns,
        do: Application.put_env(:sigil_guard, :scanner_patterns, original_patterns),
        else: Application.delete_env(:sigil_guard, :scanner_patterns)

      if original_backend,
        do: Application.put_env(:sigil_guard, :backend, original_backend),
        else: Application.delete_env(:sigil_guard, :backend)

      if original_url,
        do: Application.put_env(:sigil_guard, :registry_url, original_url),
        else: Application.delete_env(:sigil_guard, :registry_url)

      if original_ttl,
        do: Application.put_env(:sigil_guard, :registry_ttl_ms, original_ttl),
        else: Application.delete_env(:sigil_guard, :registry_ttl_ms)

      if original_timeout,
        do: Application.put_env(:sigil_guard, :registry_timeout_ms, original_timeout),
        else: Application.delete_env(:sigil_guard, :registry_timeout_ms)

      if original_enabled,
        do: Application.put_env(:sigil_guard, :registry_enabled, original_enabled),
        else: Application.delete_env(:sigil_guard, :registry_enabled)
    end)

    :ok
  end

  describe "backend/0" do
    test "defaults to :elixir" do
      Application.delete_env(:sigil_guard, :backend)
      assert Config.backend() == :elixir
    end

    test "returns configured backend" do
      Application.put_env(:sigil_guard, :backend, :nif)
      assert Config.backend() == :nif
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
    test "returns default URL" do
      Application.delete_env(:sigil_guard, :registry_url)
      assert Config.registry_url() == "https://registry.sigil-protocol.org"
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
end
