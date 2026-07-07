defmodule SigilGuard.BoundaryPolicy.MatchTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.BoundaryPolicy
  alias SigilGuard.BoundaryPolicy.File, as: PolicyFile

  @digest String.duplicate("a", 64)

  setup_all do
    {:ok, canonical} =
      PolicyFile.parse(SigilGuard.FixturePath.read!("boundary_policy/canonical.policy"))

    %{policy: canonical}
  end

  defp base(over) do
    Keyword.merge(
      [
        phase: :model_egress,
        source: :tool,
        sink: :model,
        action_digest: @digest,
        payload_digest: @digest,
        context_digest: @digest,
        trust_level: :low
      ],
      over
    )
  end

  defp eval(over, policy) do
    decision = BoundaryPolicy.evaluate(base(over), policy: policy)
    {decision.action, Enum.map(decision.audit_metadata.matched_rules, & &1["id"])}
  end

  describe "canonical policy rule matching" do
    test "the lethal-trifecta rule blocks low/medium trust", %{policy: policy} do
      trifecta = [
        source_sensitivity: :private,
        origin: :tool,
        trust_zone: :untrusted,
        sink: :external,
        trust_level: :low
      ]

      assert {:block, ids} = eval(trifecta, policy)
      assert "line_7" in ids
    end

    test "high trust in the trifecta routes to confirm", %{policy: policy} do
      assert {:confirm, ids} =
               eval(
                 [
                   source_sensitivity: :private,
                   origin: :tool,
                   trust_zone: :untrusted,
                   sink: :external,
                   trust_level: :high
                 ],
                 policy
               )

      assert "line_9" in ids
    end

    test "internal data to an external sink confirms", %{policy: policy} do
      assert {:confirm, ids} =
               eval([source_sensitivity: :internal, origin: :resource, sink: :network], policy)

      assert "line_11" in ids
    end

    test "no matching rule falls back to the policy default", %{policy: policy} do
      assert {:allow, ["policy.default"]} =
               eval([source_sensitivity: :public, origin: :user, sink: :model], policy)
    end

    test "model ingress with an injection indicator quarantines", %{policy: policy} do
      assert {:quarantine, ids} =
               eval(
                 [
                   phase: :model_ingress,
                   origin: :tool,
                   indicators: [%{"category" => :injection}]
                 ],
                 policy
               )

      assert "line_18" in ids
    end

    test "a sandboxed read at tool_result is allowed by the override rule", %{policy: policy} do
      assert {:allow, ids} =
               eval(
                 [
                   phase: :tool_result,
                   sandbox: %{"isolation_level" => :container},
                   tool: %{"name" => "reader", "side_effects" => [:read]}
                 ],
                 policy
               )

      assert "line_22" in ids
    end
  end

  describe "matcher semantics" do
    defp compile!(source), do: elem(PolicyFile.parse(source), 1)

    test "star matches any present tool but requires the actor to match" do
      policy = compile!("version 3\n[rules]\nblock tool:* actor:svc:bot\n")

      assert {:block, ["line_3"]} =
               eval([tool: %{"name" => "anything"}, actor: %{"id" => "svc:bot"}], policy)

      # actor mismatch -> the rule does not fire, falling back to absent default
      assert {:confirm, ["policy.default.absent"]} =
               eval([tool: %{"name" => "x"}, actor: %{"id" => "other"}], policy)
    end

    test "hits categories: secret and any both match a secret hit; the stronger wins" do
      policy = compile!("version 3\n[rules]\nredact hits:any\nconfirm hits:secret\n")
      assert {:confirm, ids} = eval([hits: [%{"category" => :secret}]], policy)
      assert "line_4" in ids
    end

    test "hits:none matches only when no hits are present" do
      policy = compile!("version 3\n[rules]\nblock hits:none\n")
      assert {:block, ["line_3"]} = eval([hits: []], policy)

      assert {:confirm, ["policy.default.absent"]} =
               eval([hits: [%{"category" => :secret}]], policy)
    end

    test "indicator:none matches when no indicators are present" do
      policy = compile!("version 3\n[rules]\nblock indicator:none\n")
      assert {:block, ["line_3"]} = eval([indicators: []], policy)

      assert {:confirm, ["policy.default.absent"]} =
               eval([indicators: [%{"category" => :injection}]], policy)
    end

    test "effect intersects the tool side-effect classes" do
      policy = compile!("version 3\n[rules]\nblock effect:execute,network\n")
      assert {:block, ["line_3"]} = eval([tool: %{"side_effects" => [:read, :network]}], policy)

      assert {:confirm, ["policy.default.absent"]} =
               eval([tool: %{"side_effects" => [:read]}], policy)
    end

    test "isolation:absent matches a nil level; a level value matches itself" do
      policy = compile!("version 3\n[rules]\nblock isolation:absent\nconfirm isolation:vm\n")
      assert {:block, ["line_3"]} = eval([], policy)
      assert {:confirm, ["line_4"]} = eval([sandbox: %{"isolation_level" => :vm}], policy)
    end

    test "source matches an exact value or a wildcard" do
      policy = compile!("version 3\n[rules]\nblock source:repo\nconfirm source:*\n")
      assert {:block, ["line_3"]} = eval([source: :repo], policy)
      assert {:confirm, ["line_4"]} = eval([source: "session-1"], policy)
    end

    test "absent tool, actor, and category fields never match their matchers" do
      policy =
        compile!(
          "version 3\n[rules]\nblock tool:foo\nblock actor:bar\nblock hits:secret\nblock effect:read\n"
        )

      assert {:confirm, ["policy.default.absent"]} =
               eval([tool: nil, actor: nil, hits: [], indicators: []], policy)
    end

    test "nil present-in fields and unknown matcher keys do not match" do
      policy = compile!("version 3\n[rules]\nblock origin:user\nconfirm made_up:value\n")

      assert {:allow, []} = eval([origin: nil], policy)
    end

    test "malformed hit and indicator entries are skipped" do
      policy = compile!("version 3\n[rules]\nblock hits:none indicator:none\n")
      assert {:block, ["line_3"]} = eval([hits: ["not-a-map"], indicators: [42]], policy)
    end
  end
end
