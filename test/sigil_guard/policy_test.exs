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
    test "allows low-risk actions for anonymous users" do
      assert :allowed = Policy.evaluate("read_file", :anonymous)
    end

    test "allows medium-risk actions for authenticated users" do
      assert :allowed = Policy.evaluate("create_resource", :authenticated)
    end

    test "allows high-risk actions for verified users" do
      assert :allowed = Policy.evaluate("execute_command", :verified)
    end

    test "allows critical actions for sovereign users" do
      assert :allowed = Policy.evaluate("delete_database", :sovereign)
    end

    test "blocks critical actions for anonymous users" do
      assert :blocked = Policy.evaluate("delete_database", :anonymous)
    end

    test "blocks high-risk actions for anonymous users" do
      assert :blocked = Policy.evaluate("execute_command", :anonymous)
    end

    test "offers confirmation when one trust level below" do
      # Medium risk needs :authenticated, anonymous is one below
      assert {:confirm, reason} = Policy.evaluate("create_resource", :anonymous)
      assert is_binary(reason)
      assert String.contains?(reason, "create_resource")
    end

    test "offers confirmation for high-risk with authenticated trust" do
      assert {:confirm, _reason} = Policy.evaluate("write_file", :authenticated)
    end

    test "accepts risk_level override" do
      assert :blocked = Policy.evaluate("innocent_action", :anonymous, risk_level: :critical)
    end

    test "accepts custom trust_thresholds" do
      thresholds = %{
        none: :anonymous,
        low: :anonymous,
        medium: :anonymous,
        high: :anonymous,
        critical: :anonymous
      }

      assert :allowed =
               Policy.evaluate("delete_database", :anonymous, trust_thresholds: thresholds)
    end

    test "accepts custom risk_mappings" do
      mappings = %{"safe_delete" => :low}
      assert :allowed = Policy.evaluate("safe_delete", :anonymous, risk_mappings: mappings)
    end
  end

  describe "classify_risk/2" do
    test "classifies delete_ as critical" do
      assert :critical = Policy.classify_risk("delete_user")
    end

    test "classifies drop_ as critical" do
      assert :critical = Policy.classify_risk("drop_table")
    end

    test "classifies destroy_ as critical" do
      assert :critical = Policy.classify_risk("destroy_session")
    end

    test "classifies write_ as high" do
      assert :high = Policy.classify_risk("write_file")
    end

    test "classifies update_ as high" do
      assert :high = Policy.classify_risk("update_config")
    end

    test "classifies execute_ as high" do
      assert :high = Policy.classify_risk("execute_query")
    end

    test "classifies run_ as high" do
      assert :high = Policy.classify_risk("run_migration")
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
      mappings = %{"custom_action" => :critical}
      assert :critical = Policy.classify_risk("custom_action", risk_mappings: mappings)
    end
  end

  describe "trust_threshold/1" do
    test "returns correct defaults for all risk levels" do
      assert :anonymous = Policy.trust_threshold(:none)
      assert :anonymous = Policy.trust_threshold(:low)
      assert :authenticated = Policy.trust_threshold(:medium)
      assert :verified = Policy.trust_threshold(:high)
      assert :sovereign = Policy.trust_threshold(:critical)
    end
  end

  describe "risk_levels/0" do
    test "returns all risk levels in ascending order" do
      assert [:none, :low, :medium, :high, :critical] = Policy.risk_levels()
    end
  end

  describe "compare_risk/2" do
    test "lower risk is :lt" do
      assert :lt = Policy.compare_risk(:low, :high)
    end

    test "higher risk is :gt" do
      assert :gt = Policy.compare_risk(:critical, :medium)
    end

    test "equal risk is :eq" do
      assert :eq = Policy.compare_risk(:medium, :medium)
    end

    test "none is less than all others" do
      for level <- [:low, :medium, :high, :critical] do
        assert :lt = Policy.compare_risk(:none, level)
      end
    end
  end

  describe "trust monotonicity" do
    test "higher trust always subsumes lower trust for any risk level" do
      trust_levels = [:anonymous, :authenticated, :verified, :sovereign]
      risk_levels = [:none, :low, :medium, :high, :critical]

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
      # Use a unique table for this test to avoid conflicts
      table = :rate_test_allows

      assert :ok = Policy.rate_check("user1", max_requests: 5, rate_store: table)
      assert :ok = Policy.rate_check("user1", max_requests: 5, rate_store: table)
    end

    test "blocks requests exceeding limit" do
      table = :rate_test_blocks

      for _i <- 1..3 do
        Policy.rate_check("user2", max_requests: 3, rate_store: table)
      end

      assert {:error, :rate_limited} =
               Policy.rate_check("user2", max_requests: 3, rate_store: table)
    end

    test "different identities have independent limits" do
      table = :rate_test_independent

      for _i <- 1..3 do
        Policy.rate_check("alice", max_requests: 3, rate_store: table)
      end

      assert {:error, :rate_limited} =
               Policy.rate_check("alice", max_requests: 3, rate_store: table)

      assert :ok = Policy.rate_check("bob", max_requests: 3, rate_store: table)
    end
  end
end
