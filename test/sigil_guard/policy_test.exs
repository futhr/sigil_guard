defmodule SigilGuard.PolicyTest do
  @moduledoc """
  Tests for `SigilGuard.Policy`.

  Validates risk classification (`classify_risk/2`) and trust-gated policy
  evaluation (`evaluate/3`) across all risk levels and trust tiers, including
  custom policy overrides.
  """

  use ExUnit.Case, async: true

  doctest SigilGuard.Policy

  alias SigilGuard.Policy

  describe "evaluate/3" do
    test "allows low-risk actions for low trust users" do
      assert :allowed = Policy.evaluate("read_file", :low)
    end

    test "allows medium-risk actions for medium trust users" do
      assert :allowed = Policy.evaluate("create_resource", :medium)
    end

    test "allows high-risk actions for high trust users" do
      assert :allowed = Policy.evaluate("delete_database", :high)
    end

    test "blocks high-risk actions for low trust users" do
      assert :blocked = Policy.evaluate("delete_database", :low)
    end

    test "offers confirmation when one trust level below" do
      # Medium risk needs :medium, low is one below
      assert {:confirm, reason} = Policy.evaluate("create_resource", :low)
      assert is_binary(reason)
      assert String.contains?(reason, "create_resource")
    end

    test "offers confirmation for high-risk with medium trust" do
      assert {:confirm, _} = Policy.evaluate("delete_database", :medium)
    end

    test "accepts risk_level override" do
      assert :blocked = Policy.evaluate("innocent_action", :low, risk_level: :high)
    end

    test "accepts custom trust_thresholds" do
      thresholds = %{
        low: :low,
        medium: :low,
        high: :low
      }

      assert :allowed =
               Policy.evaluate("delete_database", :low, trust_thresholds: thresholds)
    end

    test "accepts custom risk_mappings" do
      mappings = %{"safe_delete" => :low}
      assert :allowed = Policy.evaluate("safe_delete", :low, risk_mappings: mappings)
    end
  end

  describe "classify_risk/2" do
    test "classifies delete_ as high" do
      assert :high = Policy.classify_risk("delete_user")
    end

    test "classifies drop_ as high" do
      assert :high = Policy.classify_risk("drop_table")
    end

    test "classifies destroy_ as high" do
      assert :high = Policy.classify_risk("destroy_session")
    end

    test "classifies execute_ as high" do
      assert :high = Policy.classify_risk("execute_query")
    end

    test "classifies run_ as high" do
      assert :high = Policy.classify_risk("run_migration")
    end

    test "classifies write_ as medium" do
      assert :medium = Policy.classify_risk("write_file")
    end

    test "classifies update_ as medium" do
      assert :medium = Policy.classify_risk("update_config")
    end

    test "classifies create_ as medium" do
      assert :medium = Policy.classify_risk("create_user")
    end

    test "classifies modify_ as medium" do
      assert :medium = Policy.classify_risk("modify_settings")
    end

    test "classifies send_ as medium" do
      assert :medium = Policy.classify_risk("send_email")
    end

    test "classifies read_ as low" do
      assert :low = Policy.classify_risk("read_file")
    end

    test "classifies get_ as low" do
      assert :low = Policy.classify_risk("get_user")
    end

    test "classifies list_ as low" do
      assert :low = Policy.classify_risk("list_files")
    end

    test "classifies search_ as low" do
      assert :low = Policy.classify_risk("search_index")
    end

    test "defaults unknown prefixes to medium" do
      assert :medium = Policy.classify_risk("something_else")
    end

    test "uses custom risk_mappings" do
      mappings = %{"custom_action" => :high}
      assert :high = Policy.classify_risk("custom_action", risk_mappings: mappings)
    end
  end

  describe "trust_threshold/1" do
    test "returns correct defaults for all risk levels" do
      assert :low = Policy.trust_threshold(:low)
      assert :medium = Policy.trust_threshold(:medium)
      assert :high = Policy.trust_threshold(:high)
    end
  end

  describe "risk_levels/0" do
    test "returns all risk levels in ascending order" do
      assert [:low, :medium, :high] = Policy.risk_levels()
    end
  end

  describe "compare_risk/2" do
    test "lower risk is :lt" do
      assert :lt = Policy.compare_risk(:low, :high)
    end

    test "higher risk is :gt" do
      assert :gt = Policy.compare_risk(:high, :medium)
    end

    test "equal risk is :eq" do
      assert :eq = Policy.compare_risk(:medium, :medium)
    end

    test "low is less than all others" do
      for level <- [:medium, :high] do
        assert :lt = Policy.compare_risk(:low, level)
      end
    end
  end

  describe "trust monotonicity" do
    test "higher trust always subsumes lower trust for any risk level" do
      trust_levels = [:low, :medium, :high]
      risk_levels = [:low, :medium, :high]

      for risk <- risk_levels do
        verdicts =
          Enum.map(trust_levels, fn trust ->
            Policy.evaluate("test_action", trust, risk_level: risk)
          end)

        # Once :allowed appears, all higher trust levels should also be :allowed
        Enum.reduce(verdicts, false, fn verdict, saw_allowed ->
          if saw_allowed do
            assert verdict == :allowed,
                   "Trust monotonicity violated: risk=#{risk}, higher trust got #{inspect(verdict)} after :allowed"

            true
          else
            verdict == :allowed
          end
        end)
      end
    end
  end

  describe "rate_check/2" do
    test "allows requests within limit" do
      table = :rate_test_allows

      assert :ok = Policy.rate_check("user1", max_requests: 5, rate_store: table)
      assert :ok = Policy.rate_check("user1", max_requests: 5, rate_store: table)
    end

    test "blocks requests exceeding limit" do
      table = :rate_test_blocks

      for _ <- 1..3 do
        Policy.rate_check("user2", max_requests: 3, rate_store: table)
      end

      assert {:error, :rate_limited} =
               Policy.rate_check("user2", max_requests: 3, rate_store: table)
    end

    test "different identities have independent limits" do
      table = :rate_test_independent

      for _ <- 1..3 do
        Policy.rate_check("alice", max_requests: 3, rate_store: table)
      end

      assert {:error, :rate_limited} =
               Policy.rate_check("alice", max_requests: 3, rate_store: table)

      assert :ok = Policy.rate_check("bob", max_requests: 3, rate_store: table)
    end
  end
end
