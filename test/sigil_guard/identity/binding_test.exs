defmodule SigilGuard.Identity.BindingTest do
  @moduledoc """
  Tests for `SigilGuard.Identity.Binding`.
  """

  use ExUnit.Case, async: true

  alias SigilGuard.Identity.Binding

  describe "struct" do
    test "creates binding with defaults" do
      binding = %Binding{}

      assert binding.provider == nil
      assert binding.id == nil
      assert binding.trust_level == nil
      assert binding.bound_at == nil
    end

    test "creates binding with all fields" do
      binding = %Binding{
        provider: "google",
        id: "user@example.com",
        trust_level: :medium,
        bound_at: "2026-03-02T10:00:00.000Z"
      }

      assert binding.provider == "google"
      assert binding.id == "user@example.com"
      assert binding.trust_level == :medium
      assert binding.bound_at == "2026-03-02T10:00:00.000Z"
    end
  end
end
