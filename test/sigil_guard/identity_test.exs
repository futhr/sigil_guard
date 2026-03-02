defmodule SigilGuard.IdentityTest do
  @moduledoc """
  Tests for `SigilGuard.Identity`.

  Validates trust level comparison, ordering, minimum trust requirements,
  and the trust level hierarchy (anonymous < authenticated < verified < sovereign).
  """

  use ExUnit.Case, async: true

  doctest SigilGuard.Identity

  alias SigilGuard.Identity

  describe "compare_trust/2" do
    test "anonymous < authenticated" do
      assert :lt = Identity.compare_trust(:anonymous, :authenticated)
    end

    test "authenticated < verified" do
      assert :lt = Identity.compare_trust(:authenticated, :verified)
    end

    test "verified < sovereign" do
      assert :lt = Identity.compare_trust(:verified, :sovereign)
    end

    test "equal levels return :eq" do
      for level <- Identity.trust_levels() do
        assert :eq = Identity.compare_trust(level, level)
      end
    end

    test "higher trust returns :gt" do
      assert :gt = Identity.compare_trust(:sovereign, :anonymous)
      assert :gt = Identity.compare_trust(:verified, :authenticated)
    end

    test "full ordering is transitive" do
      levels = Identity.trust_levels()

      for {a, i} <- Enum.with_index(levels),
          {b, j} <- Enum.with_index(levels) do
        expected =
          cond do
            i < j -> :lt
            i > j -> :gt
            true -> :eq
          end

        assert Identity.compare_trust(a, b) == expected,
               "compare_trust(#{a}, #{b}) expected #{expected}"
      end
    end
  end

  describe "sufficient_trust?/2" do
    test "same level is sufficient" do
      for level <- Identity.trust_levels() do
        assert Identity.sufficient_trust?(level, level)
      end
    end

    test "higher level is sufficient" do
      assert Identity.sufficient_trust?(:sovereign, :anonymous)
      assert Identity.sufficient_trust?(:verified, :authenticated)
      assert Identity.sufficient_trust?(:authenticated, :anonymous)
    end

    test "lower level is insufficient" do
      refute Identity.sufficient_trust?(:anonymous, :authenticated)
      refute Identity.sufficient_trust?(:authenticated, :verified)
      refute Identity.sufficient_trust?(:verified, :sovereign)
    end

    test "anonymous is only sufficient for anonymous" do
      assert Identity.sufficient_trust?(:anonymous, :anonymous)
      refute Identity.sufficient_trust?(:anonymous, :authenticated)
      refute Identity.sufficient_trust?(:anonymous, :verified)
      refute Identity.sufficient_trust?(:anonymous, :sovereign)
    end

    test "sovereign is sufficient for all levels" do
      for level <- Identity.trust_levels() do
        assert Identity.sufficient_trust?(:sovereign, level)
      end
    end
  end

  describe "trust_levels/0" do
    test "returns all four levels in ascending order" do
      assert [:anonymous, :authenticated, :verified, :sovereign] = Identity.trust_levels()
    end
  end
end
