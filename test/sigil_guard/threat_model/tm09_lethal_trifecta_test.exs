defmodule SigilGuard.ThreatModel.TM09LethalTrifectaTest do
  @moduledoc false

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias SigilGuard.BoundaryPolicy
  alias SigilGuard.BoundaryPolicy.File, as: PolicyFile
  alias SigilGuard.BoundaryPolicyFixture

  @digest String.duplicate("a", 64)

  setup do
    {:ok, policy} = PolicyFile.parse(File.read!(BoundaryPolicyFixture.canonical_path()))
    %{policy: policy}
  end

  describe "the lethal trifecta blocks or confirms by trust level (row 10, mitigates)" do
    test "low and medium trust are blocked outright", %{policy: policy} do
      assert BoundaryPolicy.evaluate(trifecta(trust_level: :low), policy: policy).action == :block

      assert BoundaryPolicy.evaluate(trifecta(trust_level: :medium), policy: policy).action ==
               :block
    end

    test "high trust routes to a confirmation", %{policy: policy} do
      decision = BoundaryPolicy.evaluate(trifecta(trust_level: :high), policy: policy)

      assert decision.action == :confirm
      assert match?({:confirm, _}, decision.verdict)
    end
  end

  describe "every leg of the trifecta is required (row 10, conjunct coverage)" do
    property "dropping any single leg no longer blocks, at any trust level", %{policy: policy} do
      check all(
              dropped <- member_of([:private_data, :untrusted_exposure, :external_sink]),
              trust <- member_of([:low, :medium, :high])
            ) do
        leg =
          case dropped do
            :private_data -> %{source_sensitivity: :public}
            :untrusted_exposure -> %{trust_zone: :trusted}
            :external_sink -> %{sink: :model}
          end

        boundary = trifecta(Map.put(leg, :trust_level, trust))

        assert BoundaryPolicy.evaluate(boundary, policy: policy).action == :allow
      end
    end
  end

  describe "untrusted-origin content cannot reach an execution sink (row 11, mitigates dataflow)" do
    test "untrusted content requesting a tool is blocked before execution" do
      decision =
        BoundaryPolicy.evaluate(%{
          phase: :tool_request,
          source: :tool,
          sink: :tool,
          origin: :tool,
          trust_zone: :untrusted,
          trust_level: :low,
          action_digest: @digest,
          payload_digest: @digest,
          context_digest: @digest
        })

      assert decision.action == :block
      assert decision.reason == "untrusted zone may not request tools"
    end

    test "an execute side-effect without isolation is blocked; the runtime that executes is out of scope" do
      decision =
        BoundaryPolicy.evaluate(%{
          phase: :tool_request,
          source: :tool,
          sink: :tool,
          origin: :tool,
          trust_level: :high,
          action_digest: @digest,
          payload_digest: @digest,
          context_digest: @digest,
          tool: %{"side_effects" => [:execute], "manifest_digest" => String.duplicate("b", 64)},
          sandbox: %{"isolation_level" => :none}
        })

      assert decision.action == :block

      assert "sandbox.matrix.execute.none" in Enum.map(
               decision.audit_metadata.matched_rules,
               & &1["id"]
             )
    end
  end

  describe "the deterministic kernel is label-driven (tamper) and fails closed (malformed)" do
    test "a scrubbed, benign-looking payload still blocks the trifecta", %{policy: policy} do
      # The verdict is computed from dataflow labels, not from content
      # classification, so masking the visible payload does not bypass the block.
      boundary = trifecta(trust_level: :low, hits: [], indicators: [])

      assert BoundaryPolicy.evaluate(boundary, policy: policy).action == :block
    end

    test "a boundary missing required digests fails closed", %{policy: policy} do
      boundary =
        trifecta(trust_level: :low)
        |> Map.drop([:action_digest, :payload_digest, :context_digest])

      assert BoundaryPolicy.evaluate(boundary, policy: policy).action == :block
    end
  end

  # A boundary carrying all three lethal-trifecta legs: private data, untrusted
  # content exposure (untrusted origin + zone), and an external-communication
  # sink. The fully-attested sandbox keeps the side-effect matrix a no-op so the
  # trifecta rule is what decides.
  defp trifecta(over) do
    Map.merge(
      %{
        phase: :model_egress,
        source: :tool,
        sink: :external,
        origin: :tool,
        source_sensitivity: :private,
        trust_zone: :untrusted,
        trust_level: :low,
        action_digest: @digest,
        payload_digest: @digest,
        context_digest: @digest,
        sandbox: %{"isolation_level" => :remote_attested}
      },
      Map.new(over)
    )
  end
end
