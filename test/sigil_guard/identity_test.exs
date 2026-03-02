defmodule SigilGuard.IdentityTest do
  @moduledoc """
  Tests for `SigilGuard.Identity`.

  Validates trust level comparison, ordering, minimum trust requirements,
  and the trust level hierarchy (low < medium < high).
  """

  use ExUnit.Case, async: true

  doctest SigilGuard.Identity

  alias SigilGuard.Identity

  describe "compare_trust/2" do
    test "low < medium" do
      assert :lt = Identity.compare_trust(:low, :medium)
    end

    test "medium < high" do
      assert :lt = Identity.compare_trust(:medium, :high)
    end

    test "equal levels return :eq" do
      for level <- Identity.trust_levels() do
        assert :eq = Identity.compare_trust(level, level)
      end
    end

    test "higher trust returns :gt" do
      assert :gt = Identity.compare_trust(:high, :low)
      assert :gt = Identity.compare_trust(:medium, :low)
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
      assert Identity.sufficient_trust?(:high, :low)
      assert Identity.sufficient_trust?(:high, :medium)
      assert Identity.sufficient_trust?(:medium, :low)
    end

    test "lower level is insufficient" do
      refute Identity.sufficient_trust?(:low, :medium)
      refute Identity.sufficient_trust?(:medium, :high)
    end

    test "low is only sufficient for low" do
      assert Identity.sufficient_trust?(:low, :low)
      refute Identity.sufficient_trust?(:low, :medium)
      refute Identity.sufficient_trust?(:low, :high)
    end

    test "high is sufficient for all levels" do
      for level <- Identity.trust_levels() do
        assert Identity.sufficient_trust?(:high, level)
      end
    end
  end

  describe "trust_levels/0" do
    test "returns all three levels in ascending order" do
      assert [:low, :medium, :high] = Identity.trust_levels()
    end
  end
end
