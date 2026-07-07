defmodule SigilGuard.Audit.EvidenceTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Attestation
  alias SigilGuard.Audit
  alias SigilGuard.Audit.Anchor
  alias SigilGuard.Audit.Checkpoint
  alias SigilGuard.Audit.Evidence
  alias SigilGuard.Audit.Export
  alias SigilGuard.Context
  alias SigilGuard.Decision

  @chain_key :crypto.hash(:sha256, "evidence test chain key")
  @generated_at "2026-07-02T12:00:03.000Z"

  setup do
    events =
      0..2
      |> Enum.map(&Audit.new_event("runtime.gate", "actor", "act#{&1}", "ok"))
      |> Audit.build_chain(@chain_key)

    {:ok, checkpoint} = Checkpoint.create(events, generated_at: @generated_at)
    {:ok, export} = Export.create(events, generated_at: @generated_at)

    anchor =
      Anchor.create(checkpoint, anchored_at: @generated_at, storage: :local_file, uri: "file://a")

    %{events: events, checkpoint: checkpoint, export: export, anchor: anchor}
  end

  describe "ref/2" do
    test "builds a ref whose digest is the artifact's digest", ctx do
      assert Evidence.ref(:checkpoint, ctx.checkpoint) ==
               %{"kind" => "checkpoint", "ref" => Checkpoint.digest(ctx.checkpoint)}

      assert Evidence.ref(:export, ctx.export) ==
               %{"kind" => "export", "ref" => Export.digest(ctx.export)}

      assert Evidence.ref(:anchor, ctx.anchor) ==
               %{"kind" => "anchor", "ref" => Anchor.digest(ctx.anchor)}
    end
  end

  describe "validate/1" do
    test "accepts a well-formed ref list", ctx do
      refs = [Evidence.ref(:checkpoint, ctx.checkpoint), Evidence.ref(:export, ctx.export)]
      assert Evidence.validate(refs) == :ok
      assert Evidence.validate([]) == :ok
    end

    test "rejects malformed refs" do
      for bad <- [
            "not a list",
            [%{"kind" => "bogus", "ref" => "x"}],
            [%{"kind" => "checkpoint"}],
            [%{"kind" => "checkpoint", "ref" => ""}],
            [%{"kind" => "checkpoint", "ref" => 123}],
            ["not a map"]
          ] do
        assert Evidence.validate(bad) == {:error, :invalid_evidence}
      end
    end
  end

  describe "resolve/2" do
    test "resolves refs across kinds against the supplied artifacts", ctx do
      refs = [
        Evidence.ref(:checkpoint, ctx.checkpoint),
        Evidence.ref(:export, ctx.export),
        Evidence.ref(:anchor, ctx.anchor)
      ]

      artifacts = [{:checkpoint, ctx.checkpoint}, {:export, ctx.export}, {:anchor, ctx.anchor}]
      assert Evidence.resolve(refs, artifacts) == :ok
    end

    test "a dangling ref fails :dangling_evidence_ref", ctx do
      tampered =
        Map.put(Evidence.ref(:checkpoint, ctx.checkpoint), "ref", String.duplicate("0", 64))

      assert Evidence.resolve([tampered], [{:checkpoint, ctx.checkpoint}]) ==
               {:error, :dangling_evidence_ref}
    end

    test "a ref whose kind mismatches the artifact does not resolve", ctx do
      # The digest is correct for a checkpoint, but labelled as an export.
      mislabelled = %{"kind" => "export", "ref" => Checkpoint.digest(ctx.checkpoint)}

      assert Evidence.resolve([mislabelled], [{:checkpoint, ctx.checkpoint}]) ==
               {:error, :dangling_evidence_ref}
    end

    test "malformed input fails :invalid_evidence", ctx do
      assert Evidence.resolve("nope", [{:checkpoint, ctx.checkpoint}]) ==
               {:error, :invalid_evidence}

      assert Evidence.resolve([%{"kind" => "bad"}], [{:checkpoint, ctx.checkpoint}]) ==
               {:error, :invalid_evidence}
    end
  end

  describe "round-trip: decision -> attestation -> audit event" do
    test "the same evidence ref flows through and resolves", ctx do
      ref = Evidence.ref(:checkpoint, ctx.checkpoint)

      context = %Context{
        phase: :tool_request,
        actor: "spiffe://agents/x",
        identity: "id",
        trust_level: :medium,
        origin: :user,
        sink: :tool,
        tool: "repo_file_write"
      }

      decision =
        struct!(Decision,
          verdict: :allowed,
          action: :allow,
          phase: :tool_request,
          risk_level: :low,
          trust_level: :medium
        )

      assert {:ok, statement} =
               Attestation.from_decision(decision, context,
                 payload: %{"method" => "tools/call"},
                 evidence: [ref],
                 now: ~U[2026-07-03 12:00:00.000Z],
                 ttl_ms: 60_000
               )

      audit_event =
        "runtime.gate"
        |> Audit.new_event("actor", "act", "ok", %{"evidence" => [ref]})
        |> Audit.sign_event(@chain_key)

      # The decision's attestation and the audit event carry the identical ref.
      assert get_in(statement, ["predicate", "evidence"]) == [ref]
      assert audit_event.metadata["evidence"] == [ref]
      # And it resolves to the real checkpoint artifact.
      assert Evidence.resolve(audit_event.metadata["evidence"], [{:checkpoint, ctx.checkpoint}]) ==
               :ok
    end

    test "from_decision rejects malformed evidence with :invalid_evidence" do
      context = %Context{
        phase: :tool_request,
        actor: "spiffe://agents/x",
        trust_level: :medium,
        origin: :user,
        sink: :tool,
        tool: "repo_file_write"
      }

      decision =
        struct!(Decision,
          verdict: :allowed,
          action: :allow,
          phase: :tool_request,
          risk_level: :low,
          trust_level: :medium
        )

      assert Attestation.from_decision(decision, context,
               payload: %{"method" => "tools/call"},
               evidence: [%{"kind" => "bogus", "ref" => "x"}]
             ) == {:error, :invalid_evidence}
    end
  end
end
