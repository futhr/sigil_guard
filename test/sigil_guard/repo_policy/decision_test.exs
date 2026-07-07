defmodule SigilGuard.RepoPolicy.DecisionTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.RepoPolicy.Decision

  test "requires deterministic repo-policy decision fields" do
    decision = %Decision{
      verdict: :require_approval,
      reason: "matched rule",
      agent: "did:web:agent",
      action: "modify",
      changed_paths: ["lib/app.ex"],
      matched_rule_ids: ["review"],
      unmatched_paths: [],
      digest: String.duplicate("a", 64)
    }

    assert decision.verdict == :require_approval
    assert decision.changed_paths == ["lib/app.ex"]
    assert decision.matched_rule_ids == ["review"]
    assert decision.unmatched_paths == []
  end
end
