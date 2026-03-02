defmodule SigilGuard.BackendTest do
  @moduledoc """
  Tests for `SigilGuard.Backend`.

  Verifies backend dispatch: `resolve/0` returns the correct module for
  each configured backend atom, and `available?/1` correctly detects
  whether a backend's dependencies are loaded.
  """

  use ExUnit.Case, async: false

  doctest SigilGuard.Backend

  alias SigilGuard.Backend

  setup do
    original = Application.get_env(:sigil_guard, :backend)
    on_exit(fn -> Application.put_env(:sigil_guard, :backend, original || :elixir) end)
    :ok
  end

  describe "impl/0" do
    test "returns Elixir backend by default" do
      Application.put_env(:sigil_guard, :backend, :elixir)
      assert Backend.impl() == SigilGuard.Backend.Elixir
    end

    test "returns NIF backend when configured" do
      Application.put_env(:sigil_guard, :backend, :nif)
      assert Backend.impl() == SigilGuard.Backend.NIF
    end

    test "accepts custom module" do
      Application.put_env(:sigil_guard, :backend, SigilGuard.Backend.Elixir)
      assert Backend.impl() == SigilGuard.Backend.Elixir
    end
  end

  describe "available?/1" do
    test "elixir backend is always available" do
      assert Backend.available?(:elixir)
    end

    test "nif backend availability depends on compilation" do
      # NIF is not compiled in test by default
      assert is_boolean(Backend.available?(:nif))
    end
  end

  describe "available_backends/0" do
    test "always includes :elixir" do
      assert :elixir in Backend.available_backends()
    end
  end

  describe "facade dispatch" do
    test "scan dispatches through backend" do
      assert {:ok, "safe"} = SigilGuard.scan("safe")
    end

    test "scan_and_redact dispatches through backend" do
      assert "safe" = SigilGuard.scan_and_redact("safe")
    end

    test "policy_verdict dispatches through backend" do
      assert :allowed = SigilGuard.policy_verdict("read_file", :authenticated)
    end
  end
end
