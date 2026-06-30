defmodule SigilGuard.DecisionTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Decision

  describe "verdict helpers" do
    test "classify allowed, blocked, and confirmation decisions" do
      allowed = %Decision{
        verdict: :allowed,
        action: :allow,
        phase: :tool_result,
        risk_level: :low,
        trust_level: :medium
      }

      blocked = %Decision{
        verdict: :blocked,
        action: :block,
        phase: :tool_request,
        risk_level: :high,
        trust_level: :low
      }

      confirm = %Decision{
        verdict: {:confirm, "review required"},
        action: :quarantine,
        phase: :tool_result,
        risk_level: :medium,
        trust_level: :medium
      }

      assert Decision.allowed?(allowed)
      refute Decision.allowed?(blocked)
      assert Decision.blocked?(blocked)
      refute Decision.blocked?(confirm)
      assert Decision.confirm?(confirm)
      refute Decision.confirm?(allowed)
    end
  end
end
