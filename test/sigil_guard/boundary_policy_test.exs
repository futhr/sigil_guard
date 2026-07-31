defmodule SigilGuard.BoundaryPolicyTest do
  @moduledoc false

  use ExUnit.Case, async: true

  use ExUnitProperties

  alias SigilGuard.BoundaryPolicy
  alias SigilGuard.BoundaryPolicy.File, as: PolicyFile
  alias SigilGuard.BoundaryPolicyFixture
  alias SigilGuard.Decision

  doctest BoundaryPolicy

  @digest String.duplicate("a", 64)

  defmodule RequestConfirmHook do
    @spec on_tool_request(term(), term()) :: term()
    def on_tool_request(_, _), do: {:confirm, "confirm please"}
  end

  defmodule EgressBlockHook do
    @spec on_model_egress(term(), term()) :: term()
    def on_model_egress(_, _), do: {:block, "egress denied"}
  end

  defmodule RiskHook do
    @spec on_tool_request(term(), term()) :: term()
    def on_tool_request(_, _) do
      {:ok, :continue, %{risk_level: :high, indicators: [%{"category" => "hookflag"}]}}
    end
  end

  defmodule CrashHook do
    @spec on_tool_request(term(), term()) :: term()
    def on_tool_request(_, _), do: raise("boom")
  end

  defmodule EchoDetector do
    @spec analyze(term(), term(), keyword()) :: term()
    def analyze(_, _, opts), do: Keyword.fetch!(opts, :return)
  end

  # A fully-attested sandbox keeps the boundary policy mismatch matrix a no-op so these
  # cases isolate the kernel invariants, policy default, and combination engine;
  # the matrix itself is exercised in the sandbox-matrix describe block below.
  defp base(overrides \\ %{}) do
    Map.merge(
      %{
        phase: :tool_request,
        source: :tool,
        sink: :model,
        action_digest: @digest,
        payload_digest: @digest,
        context_digest: @digest,
        trust_level: :high,
        sandbox: %{"isolation_level" => :remote_attested}
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

  describe "sandbox mismatch matrix" do
    @manifest String.duplicate("b", 64)

    # boundary policy Side-Effect Mismatch Matrix. Columns: absent | :none | :container |
    # :vm | :remote_attested. `absent` is the omitted level (no sandbox).
    @matrix %{
      read: [:quarantine, :quarantine, :allow, :allow, :allow],
      write: [:quarantine, :quarantine, :confirm, :allow, :allow],
      execute: [:quarantine, :block, :confirm, :allow, :allow],
      network: [:quarantine, :block, :confirm, :allow, :allow]
    }
    @levels [:absent, :none, :container, :vm, :remote_attested]

    defp cell(class, level) do
      tool = %{"name" => "t", "manifest_digest" => @manifest, "side_effects" => [class]}

      overrides =
        case level do
          :absent -> %{phase: :tool_result, tool: tool}
          level -> %{phase: :tool_result, tool: tool, sandbox: %{"isolation_level" => level}}
        end

      # base/1 supplies a remote_attested sandbox; drop it so `:absent` is truly
      # absent, then re-apply the per-cell overrides.
      base(overrides) |> Map.drop(if level == :absent, do: [:sandbox], else: [])
    end

    for {class, verdicts} <- @matrix,
        {level, expected} <- Enum.zip(@levels, verdicts) do
      test "#{class} at #{level} isolation resolves to #{expected}" do
        decision = BoundaryPolicy.evaluate(cell(unquote(class), unquote(level)))
        assert decision.action == unquote(expected)
      end
    end

    test "matrix covers exactly the 20 documented cells" do
      assert map_size(@matrix) == 4
      assert Enum.all?(@matrix, fn {_, verdicts} -> length(verdicts) == 5 end)
      assert length(@levels) == 5
    end

    test "an absent/none quarantine records reason :sandbox_required and the cell rule id" do
      decision = BoundaryPolicy.evaluate(cell(:read, :absent))
      assert decision.action == :quarantine
      assert decision.reason == "sandbox_required"
      ids = Enum.map(decision.audit_metadata.matched_rules, & &1["id"])
      assert "sandbox.matrix.read.absent" in ids
    end

    test "an affirmative :none blocks execute and network with the cell rule id" do
      decision = BoundaryPolicy.evaluate(cell(:execute, :none))
      assert decision.action == :block

      assert "sandbox.matrix.execute.none" in Enum.map(
               decision.audit_metadata.matched_rules,
               & &1["id"]
             )
    end

    test "a declared but unverified manifest is treated as class execute" do
      # A declared tool with no manifest_digest fails closed to execute: absent
      # isolation quarantines, affirmative :none blocks.
      unverified = %{phase: :tool_result, tool: %{"name" => "t", "side_effects" => [:read]}}

      assert BoundaryPolicy.evaluate(base(unverified) |> Map.delete(:sandbox)).action ==
               :quarantine

      none_level = Map.put(unverified, :sandbox, %{"isolation_level" => :none})
      assert BoundaryPolicy.evaluate(none_level).action == :block
    end

    test "a tool-phase boundary declaring neither tool nor sandbox is out of scope" do
      # runtime opt-in-by-presence: with no tool and no sandbox there is nothing to
      # evaluate, so the matrix does not fire (the runtime gate stays opt-in).
      for phase <- [:tool_request, :tool_result] do
        boundary = base(%{phase: phase}) |> Map.drop([:sandbox, :tool])
        assert BoundaryPolicy.evaluate(boundary).action == :allow, inspect(phase)
      end
    end

    test "a tool with multiple side-effect classes uses the strictest cell" do
      tool = %{
        "name" => "t",
        "manifest_digest" => @manifest,
        "side_effects" => [:read, :execute]
      }

      # container: read allows, execute confirms -> confirm (the stricter cell).
      decision =
        BoundaryPolicy.evaluate(
          base(%{phase: :tool_result, tool: tool, sandbox: %{"isolation_level" => :container}})
        )

      assert decision.action == :confirm
    end

    test "the matrix does not apply outside the tool phases" do
      decision =
        BoundaryPolicy.evaluate(
          base(%{phase: :model_egress, source: :model, sink: :external})
          |> Map.delete(:sandbox)
        )

      assert decision.action == :allow
    end

    test "an isolation: rule is the only sanctioned override of a matrix cell" do
      {:ok, policy} =
        SigilGuard.BoundaryPolicy.File.parse(
          "version 3\n[rules]\nallow phase:tool_result isolation:none effect:execute\n"
        )

      # Without the override, execute at :none blocks; the isolation: rule weakens
      # it to allow. A non-isolation rule could not (strongest-wins would keep it).
      boundary =
        base(%{
          phase: :tool_result,
          tool: %{"name" => "t", "manifest_digest" => @manifest, "side_effects" => [:execute]},
          sandbox: %{"isolation_level" => :none}
        })

      assert BoundaryPolicy.evaluate(boundary).action == :block
      assert BoundaryPolicy.evaluate(boundary, policy: policy).action == :allow
    end

    test "an isolation: override never weakens a kernel invariant" do
      {:ok, policy} =
        SigilGuard.BoundaryPolicy.File.parse(
          "version 3\n[rules]\nallow phase:tool_request isolation:none\n"
        )

      # The untrusted-tool-request invariant still blocks even though the
      # isolation: rule allows and suppresses the matrix contribution.
      boundary =
        base(%{
          phase: :tool_request,
          trust_zone: :untrusted,
          tool: %{"name" => "t", "manifest_digest" => @manifest, "side_effects" => [:read]},
          sandbox: %{"isolation_level" => :none}
        })

      assert BoundaryPolicy.evaluate(boundary, policy: policy).action == :block
    end
  end

  describe "lethal trifecta (canonical policy)" do
    setup do
      {:ok, policy} = PolicyFile.parse(File.read!(BoundaryPolicyFixture.canonical_path()))
      %{policy: policy}
    end

    # The trifecta conjunction from the shipped canonical policy: private data,
    # untrusted-content exposure (untrusted origin + zone), and an external sink.
    defp trifecta(over) do
      base(
        Map.merge(
          %{
            phase: :model_egress,
            source: :tool,
            sink: :external,
            origin: :tool,
            source_sensitivity: :private,
            trust_zone: :untrusted
          },
          Map.new(over)
        )
      )
    end

    test "low and medium trust block outright", %{policy: policy} do
      assert BoundaryPolicy.evaluate(trifecta(trust_level: :low), policy: policy).action == :block

      assert BoundaryPolicy.evaluate(trifecta(trust_level: :medium), policy: policy).action ==
               :block
    end

    test "high trust routes to confirm", %{policy: policy} do
      decision = BoundaryPolicy.evaluate(trifecta(trust_level: :high), policy: policy)
      assert decision.action == :confirm
      assert match?({:confirm, _}, decision.verdict)
      assert "line_9" in Enum.map(decision.audit_metadata.matched_rules, & &1["id"])
    end

    test "dropping the private-data leg no longer blocks", %{policy: policy} do
      boundary = trifecta(trust_level: :low, source_sensitivity: :public)
      assert BoundaryPolicy.evaluate(boundary, policy: policy).action == :allow
    end

    test "dropping the untrusted-exposure leg no longer blocks", %{policy: policy} do
      boundary = trifecta(trust_level: :low, trust_zone: :trusted)
      assert BoundaryPolicy.evaluate(boundary, policy: policy).action == :allow
    end

    test "dropping the external-sink leg no longer blocks", %{policy: policy} do
      boundary = trifecta(trust_level: :low, sink: :model)
      assert BoundaryPolicy.evaluate(boundary, policy: policy).action == :allow
    end

    property "trust partitions the verdict: low/medium block, high confirms", %{policy: policy} do
      check all(trust <- member_of([:low, :medium, :high])) do
        action = BoundaryPolicy.evaluate(trifecta(trust_level: trust), policy: policy).action
        assert action == if(trust == :high, do: :confirm, else: :block)
      end
    end
  end

  describe "repo policy facts" do
    defp facts(over) do
      Map.merge(
        %{
          verdict: :allow,
          matched_rules: [],
          unmatched_paths: [],
          policy_file_digest: @digest,
          default_decision: :allow
        },
        Map.new(over)
      )
    end

    test "a repo block contributes block with the namespaced rule id and explanation" do
      repo =
        facts(
          verdict: :block,
          matched_rules: [%{rule_id: "line_3", explanation: "secrets are locked"}]
        )

      decision = BoundaryPolicy.evaluate(base(), repo_facts: repo)
      assert decision.action == :block
      rules = decision.audit_metadata.matched_rules
      assert "repo.line_3" in Enum.map(rules, & &1["id"])
      assert Enum.any?(rules, &(&1["explanation"] == "secrets are locked"))
    end

    test "a repo require_approval contributes confirm" do
      repo =
        facts(
          verdict: :require_approval,
          matched_rules: [%{rule_id: "line_5", explanation: "needs review"}]
        )

      decision = BoundaryPolicy.evaluate(base(), repo_facts: repo)
      assert decision.action == :confirm
      assert "repo.line_5" in Enum.map(decision.audit_metadata.matched_rules, & &1["id"])
    end

    test "a repo allow contributes nothing" do
      assert BoundaryPolicy.evaluate(base(), repo_facts: facts(verdict: :allow)).action == :allow
    end

    test "an empty matched-rules list synthesizes the repo default explanation" do
      repo = facts(verdict: :block, matched_rules: [], default_decision: :block)
      decision = BoundaryPolicy.evaluate(base(), repo_facts: repo)
      assert decision.action == :block
      assert "repo.default" in Enum.map(decision.audit_metadata.matched_rules, & &1["id"])
    end

    test "malformed repo facts are ignored, not crashed on" do
      assert BoundaryPolicy.evaluate(base(), repo_facts: :nope).action == :allow
      assert BoundaryPolicy.evaluate(base(), repo_facts: %{}).action == :allow
      assert BoundaryPolicy.evaluate(base(), repo_facts: %{verdict: :bogus}).action == :allow
    end

    test "a repo confirm cannot weaken a stronger boundary invariant" do
      decision =
        BoundaryPolicy.evaluate(base(%{trust_zone: :untrusted}),
          repo_facts: facts(verdict: :require_approval)
        )

      assert decision.action == :block
    end
  end

  describe "host hooks" do
    test "a blockable-phase hook can block, surfacing its rule id" do
      decision =
        BoundaryPolicy.evaluate(base(%{phase: :model_egress, source: :model, sink: :external}),
          hooks: [EgressBlockHook]
        )

      assert decision.action == :block

      assert "hook.#{inspect(EgressBlockHook)}.model_egress" in Enum.map(
               decision.audit_metadata.matched_rules,
               & &1["id"]
             )
    end

    test "a hook confirm routes to confirm" do
      decision = BoundaryPolicy.evaluate(base(), hooks: [RequestConfirmHook])
      assert decision.action == :confirm
    end

    test "a hook signal raises risk and appends indicators tagged :hook" do
      decision = BoundaryPolicy.evaluate(base(), hooks: [RiskHook])
      assert decision.action == :allow
      assert decision.risk_level == :high
      assert %{"category" => "hookflag", "source" => :hook} in decision.indicators
    end

    test "a crashing hook fails closed to block on a blockable phase" do
      assert BoundaryPolicy.evaluate(base(), hooks: [CrashHook]).action == :block
    end

    test "a hook confirm cannot weaken a stronger kernel invariant" do
      decision =
        BoundaryPolicy.evaluate(base(%{trust_zone: :untrusted}), hooks: [RequestConfirmHook])

      assert decision.action == :block
    end
  end

  describe "adaptive detector" do
    defp detector_opts(return), do: [adaptive_detector: EchoDetector, return: return]

    test "advisory indicators raise risk and append with source :adaptive" do
      return = {:ok, [%{id: "inj", severity: :high, confidence: 0.5}]}
      decision = BoundaryPolicy.evaluate(base(), detector_opts(return))

      # Verdict is unchanged (still allow); only risk and indicators move.
      assert decision.action == :allow
      assert decision.risk_level == :high

      assert %{id: "inj", severity: :high, confidence: 0.5, source: :adaptive} in decision.indicators
    end

    test "a degraded run records :adaptive_error and leaves risk unchanged" do
      decision = BoundaryPolicy.evaluate(base(), detector_opts({:error, :model_down}))

      assert decision.action == :allow
      assert decision.risk_level == :low
      assert decision.audit_metadata.adaptive_error == :adaptive_error
    end

    test "a clean run adds no adaptive_error key" do
      decision = BoundaryPolicy.evaluate(base(), detector_opts({:ok, []}))
      refute Map.has_key?(decision.audit_metadata, :adaptive_error)
    end

    property "with the detector unset, decisions are byte-identical to a build without it" do
      check all(
              zone <- member_of([:trusted, :semi_trusted, :untrusted, nil]),
              phase <- member_of([:tool_request, :model_ingress, :model_egress])
            ) do
        input = base(%{phase: phase, trust_zone: zone})

        assert BoundaryPolicy.evaluate(input, adaptive_detector: nil) ==
                 BoundaryPolicy.evaluate(input)
      end
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
