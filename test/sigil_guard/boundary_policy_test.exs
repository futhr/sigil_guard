defmodule SigilGuard.BoundaryPolicyTest do
  use ExUnit.Case, async: true

  use ExUnitProperties

  alias SigilGuard.BoundaryPolicy
  alias SigilGuard.Decision

  @digest String.duplicate("a", 64)

  defp base(overrides \\ %{}) do
    Map.merge(
      %{
        phase: :tool_request,
        source: :tool,
        sink: :model,
        action_digest: @digest,
        payload_digest: @digest,
        context_digest: @digest,
        trust_level: :high
      },
      Map.new(overrides)
    )
  end

  describe "evaluate/2 base and validation" do
    test "a clean boundary with no policy allows" do
      decision = BoundaryPolicy.evaluate(base())
      assert %Decision{action: :allow, verdict: :allowed, risk_level: :low} = decision
    end

    test "a malformed boundary blocks terminally with the validation reason" do
      decision = BoundaryPolicy.evaluate(base(%{phase: :bogus}))
      assert %Decision{action: :block, verdict: :blocked, reason: "invalid_phase"} = decision
    end

    test "carries phase, trust level, hits, indicators, and audit facts" do
      decision =
        BoundaryPolicy.evaluate(base(%{phase: :model_egress, sink: :external, source: :model}))

      assert decision.phase == :model_egress
      assert decision.trust_level == :high
      assert decision.audit_metadata.source == :model
      assert decision.audit_metadata.sink == :external
    end
  end

  describe "kernel invariants" do
    test "untrusted zone blocks a tool request" do
      decision = BoundaryPolicy.evaluate(base(%{trust_zone: :untrusted}))
      assert decision.action == :block
      assert decision.reason == "untrusted zone may not request tools"
    end

    test "untrusted zone outside tool_request does not trigger the invariant" do
      decision = BoundaryPolicy.evaluate(base(%{phase: :model_ingress, trust_zone: :untrusted}))
      assert decision.action == :allow
    end

    test "secret hits to an external sink block by default and redact under :on_sensitive" do
      boundary = base(%{sink: :external, hits: [%{"category" => :secret, "name" => "aws"}]})
      assert BoundaryPolicy.evaluate(boundary).action == :block
      assert BoundaryPolicy.evaluate(boundary, on_sensitive: :redact).action == :redact
    end

    test "secret hits to an internal sink do not escalate" do
      decision = BoundaryPolicy.evaluate(base(%{sink: :model, hits: [%{"category" => :secret}]}))
      assert decision.action == :allow
    end

    test "quarantine indicators quarantine" do
      decision = BoundaryPolicy.evaluate(base(%{indicators: [%{"quarantine" => true}]}))
      assert decision.action == :quarantine
      assert decision.verdict == :blocked
    end

    test "non-quarantine indicators are advisory only" do
      decision = BoundaryPolicy.evaluate(base(%{indicators: [%{"quarantine" => false}, %{}]}))
      assert decision.action == :allow
    end
  end

  describe "policy default" do
    test "a loaded policy with no default line contributes confirm" do
      decision = BoundaryPolicy.evaluate(base(), policy: %{default: nil})
      assert decision.action == :confirm
      assert match?({:confirm, _}, decision.verdict)
    end

    test "a policy default verdict is applied" do
      assert BoundaryPolicy.evaluate(base(), policy: %{default: :block}).action == :block
      assert BoundaryPolicy.evaluate(base(), policy: %{default: :redact}).action == :redact
    end

    test "a non-atom default falls back to confirm and a non-map policy is ignored" do
      assert BoundaryPolicy.evaluate(base(), policy: %{default: "block"}).action == :confirm
      assert BoundaryPolicy.evaluate(base(), policy: :not_a_policy).action == :allow
    end
  end

  describe "malformed decision inputs" do
    test "non-map hits and indicators are ignored, not crashed on" do
      boundary = base(%{sink: :external, hits: ["not-a-map"], indicators: ["x", 3]})
      assert BoundaryPolicy.evaluate(boundary).action == :allow
    end

    test "an invalid trust level on a terminally-blocked boundary floors trust at low" do
      decision = BoundaryPolicy.evaluate(base(%{trust_level: :godmode}))
      assert decision.action == :block
      assert decision.trust_level == :low
    end
  end

  describe "combination" do
    test "the strongest contribution wins" do
      decision =
        BoundaryPolicy.evaluate(
          base(%{trust_zone: :untrusted, indicators: [%{"quarantine" => true}]}),
          policy: %{default: :confirm}
        )

      assert decision.action == :block
    end

    property "evaluation is deterministic for equal inputs" do
      check all(
              zone <- member_of([:trusted, :semi_trusted, :untrusted, nil]),
              phase <- member_of([:tool_request, :model_ingress, :model_egress]),
              quarantine? <- boolean(),
              default <- member_of([nil, :allow, :confirm, :block])
            ) do
        input =
          base(%{
            phase: phase,
            trust_zone: zone,
            indicators: if(quarantine?, do: [%{"quarantine" => true}], else: [])
          })

        opts = [policy: %{default: default}]
        assert BoundaryPolicy.evaluate(input, opts) == BoundaryPolicy.evaluate(input, opts)
      end
    end
  end
end
