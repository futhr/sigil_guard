defmodule SigilGuard.Identity.StaticTest do
  @moduledoc false

  use ExUnit.Case, async: false

  use ExUnitProperties

  alias SigilGuard.Identity.Static

  setup do
    on_exit(fn -> Application.delete_env(:sigil_guard, :trust_mappings) end)
    :ok
  end

  defp put_mappings(mappings), do: Application.put_env(:sigil_guard, :trust_mappings, mappings)

  describe "identity/1 and bindings/1" do
    test "identity returns the actor string unchanged" do
      assert Static.identity("user:42") == "user:42"
    end

    test "identity maps a non-binary actor to an empty string" do
      assert Static.identity(%{actor: "x"}) == ""
      assert Static.identity(nil) == ""
    end

    test "bindings is always empty" do
      assert Static.bindings("anything") == []
    end
  end

  describe "trust_level/1" do
    test "returns :low when no mappings are configured" do
      assert Static.trust_level("user:42") == :low
    end

    test "matches an exact pattern" do
      put_mappings([{"user:42", :high}])
      assert Static.trust_level("user:42") == :high
      assert Static.trust_level("user:43") == :low
    end

    test "matches a single trailing-* prefix" do
      put_mappings([{"spiffe://prod/*", :high}])
      assert Static.trust_level("spiffe://prod/web-1") == :high
      assert Static.trust_level("spiffe://staging/web-1") == :low
    end

    test "is first-match-wins over list order" do
      put_mappings([{"user:admin", :high}, {"user:*", :medium}])
      assert Static.trust_level("user:admin") == :high
      assert Static.trust_level("user:bob") == :medium
    end

    test "a non-binary actor is :low even under a catch-all mapping" do
      put_mappings([{"*", :high}])
      assert Static.trust_level(%{}) == :low
    end

    test "malformed mapping entries are ignored defensively" do
      put_mappings([:bad, {123, :high}, {"user:*", :medium}])
      assert Static.trust_level("user:alice") == :medium
      assert Static.trust_level("service:api") == :low
    end
  end

  property "trust_level is total: every actor maps to a valid level" do
    level = member_of([:low, :medium, :high])

    check all(
            mappings <- list_of(tuple({string(:printable, max_length: 8), level}), max_length: 5),
            actor <- string(:printable, max_length: 12)
          ) do
      put_mappings(mappings)
      assert Static.trust_level(actor) in [:low, :medium, :high]
    end
  end
end
