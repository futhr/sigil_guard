defmodule SigilGuard.ThreatModel.TM12RepudiationTest do
  @moduledoc """
  TM.12 - repudiation, audit tamper, truncation, and cascades (R.06 Control
  Mapping rows 19 and 22, ASI08/ASI03, claim: **partial (evidence-only)** for
  row 19 and **mitigates + detects** for row 22).

  Control (SP.05, SP.13): signed audit events form an actor-scoped HMAC chain;
  checkpoints commit the chain with a Merkle root; inclusion and consistency
  proofs bind individual events and append-only history to externally anchored
  checkpoints. Tail truncation is not detectable from raw events alone, so this
  module verifies the SP.05 checkpoint/proof/anchor path that detects it. For
  cascading agent failures, SigilGuard does not claim automatic containment;
  per-hop attestations and audit evidence reconstruct the propagation path.

  Base-control coverage is referenced, not duplicated (by exact name):
  `SigilGuard.AuditTest` "detects tampered events in chain";
  `SigilGuard.Audit.CheckpointTest` "detects event/checkpoint mismatch";
  `SigilGuard.Audit.ProofTest` "a forked newer root fails :inconsistent_tree";
  `SigilGuard.Audit.ExportTest` "verifies signed anchored exports"; and
  `SigilGuard.Audit.EvidenceTest` "the same evidence ref flows through and
  resolves". This module composes those controls into the R.06 TM.12 threat
  family.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias SigilGuard.Attestation
  alias SigilGuard.Audit
  alias SigilGuard.Audit.Anchor
  alias SigilGuard.Audit.Checkpoint
  alias SigilGuard.Audit.Evidence
  alias SigilGuard.Audit.Export
  alias SigilGuard.Audit.Proof
  alias SigilGuard.Context
  alias SigilGuard.Decision
  alias SigilGuard.TestSigner

  @chain_key :crypto.hash(:sha256, "tm12-repudiation-audit-key")
  @generated_at "2026-07-04T10:00:00.000Z"
  @anchored_at "2026-07-04T10:00:05.000Z"
  @issuer "did:web:audit.example"

  describe "audit repudiation and tamper detection (row 22, mitigates + detects)" do
    test "HMAC chain, checkpoint, inclusion proof, and anchor bind an operator-visible event" do
      events = propagation_chain(4)

      assert :ok = Audit.verify_chain(events, @chain_key)

      assert {:ok, export} =
               Export.create(events,
                 chain_id: "tm12-chain",
                 generated_at: @generated_at,
                 signer: TestSigner,
                 issuer: @issuer,
                 issued_at: @generated_at,
                 anchor: [
                   anchored_at: @anchored_at,
                   storage: "worm",
                   uri: "worm://audit/tm12/checkpoint-4.json"
                 ],
                 inclusion_proofs: [2],
                 consistency_proof: 3
               )

      assert {:ok, verified} =
               Export.verify(export, events,
                 public_keys: %{@issuer => TestSigner.public_key_b64u()},
                 require_signature: true,
                 require_anchor: true
               )

      checkpoint = export["checkpoint"]
      [proof] = export["inclusion_proofs"]
      event = Enum.at(events, 2)

      assert verified.checkpoint.status == :verified
      assert verified.anchor.record == export["anchor"]
      assert Proof.verify_inclusion(proof, event.hmac, checkpoint["merkle_root"]) == :ok
      assert Anchor.verify(export["anchor"], checkpoint) == {:ok, verified.anchor}
    end

    test "changed event content breaks the local chain and checkpoint verification" do
      events = propagation_chain(3)
      {:ok, checkpoint} = Checkpoint.create(events, generated_at: @generated_at)

      tampered = List.update_at(events, 1, fn event -> %{event | result: "success"} end)

      hmac_tampered =
        List.update_at(events, 1, fn event -> %{event | hmac: String.duplicate("0", 64)} end)

      assert Audit.verify_chain(tampered, @chain_key) == {:broken, 1}
      assert Checkpoint.verify(checkpoint, hmac_tampered) == {:error, :broken_chain}
    end

    test "changed inclusion proof or anchor cannot support repudiated event evidence" do
      events = propagation_chain(3)
      {:ok, checkpoint} = Checkpoint.create(events, generated_at: @generated_at)
      anchor = Anchor.create(checkpoint, anchored_at: @anchored_at, storage: "worm")
      {:ok, proof} = Proof.inclusion(events, 1)

      [first_node | rest] = proof["audit_path"]
      tampered_proof = %{proof | "audit_path" => [flip_hex(first_node) | rest]}
      tampered_anchor = %{anchor | "last_hmac" => hd(events).hmac}

      assert Proof.verify_inclusion(
               tampered_proof,
               Enum.at(events, 1).hmac,
               checkpoint["merkle_root"]
             ) ==
               {:error, :proof_verification_failed}

      assert Anchor.verify(tampered_anchor, checkpoint) == {:error, :anchor_mismatch}
    end
  end

  describe "tail truncation evidence (row 22, detects)" do
    property "every proper prefix is detected against the full anchored checkpoint" do
      events = propagation_chain(12)
      {:ok, full_checkpoint} = Checkpoint.create(events, generated_at: @generated_at)

      check all(prefix_size <- integer(1..11), max_runs: 50) do
        prefix = Enum.take(events, prefix_size)
        {:ok, prefix_checkpoint} = Checkpoint.create(prefix, generated_at: @generated_at)
        {:ok, proof} = Proof.consistency(events, prefix_size)

        assert Proof.verify_consistency(
                 proof,
                 prefix_checkpoint["merkle_root"],
                 full_checkpoint["merkle_root"]
               ) == :ok

        truncated_root = prefix_checkpoint["merkle_root"]

        assert Proof.verify_consistency(proof, prefix_checkpoint["merkle_root"], truncated_root) ==
                 {:error, :inconsistent_tree}
      end
    end

    test "a forged continuation segment fails against the stored tip" do
      [first, second, third | _] = propagation_chain(4)
      forged_segment = [%{third | prev_hmac: second.hmac}]

      assert Audit.verify_chain(forged_segment, @chain_key, prev_hmac: first.hmac) ==
               {:broken, 0}
    end
  end

  describe "cascading agent failures are reconstructable, not automatically contained (row 19)" do
    test "per-hop attestations and audit evidence reconstruct the propagation path" do
      events = propagation_chain(3)
      {:ok, checkpoint} = Checkpoint.create(events, generated_at: @generated_at)
      {:ok, export} = Export.create(events, generated_at: @generated_at, anchor: true)
      anchor = export["anchor"]

      evidence = [
        Evidence.ref(:checkpoint, checkpoint),
        Evidence.ref(:export, export),
        Evidence.ref(:anchor, anchor)
      ]

      hops =
        events
        |> Enum.map(fn event ->
          %{"actor" => event.actor, "evidence" => event.metadata["hop"]}
        end)

      assert {:ok, request} =
               attested_decision(
                 :agent_request,
                 "spiffe://agents/router",
                 %{
                   "peer_agent" => "spiffe://agents/retriever",
                   "capability" => "summarize",
                   "delegation_chain" => hops
                 },
                 evidence
               )

      assert {:ok, response} =
               attested_decision(
                 :agent_response,
                 "spiffe://agents/retriever",
                 %{
                   "peer_agent" => "spiffe://agents/router",
                   "capability" => "summarize",
                   "status" => "ok"
                 },
                 evidence,
                 request_action_digest: subject_digest(request, "action")
               )

      artifacts = [{:checkpoint, checkpoint}, {:export, export}, {:anchor, anchor}]

      assert Evidence.resolve(request["predicate"]["evidence"], artifacts) == :ok
      assert Evidence.resolve(response["predicate"]["evidence"], artifacts) == :ok
      assert get_in(request, ["predicate", "delegation_chain"]) == hops

      assert Enum.map(hops, & &1["actor"]) == [
               "spiffe://agents/user-facing",
               "spiffe://agents/router",
               "spiffe://agents/retriever"
             ]
    end

    test "missing evidence makes the cascade path non-resolvable" do
      events = propagation_chain(2)
      {:ok, checkpoint} = Checkpoint.create(events, generated_at: @generated_at)
      ref = Evidence.ref(:checkpoint, checkpoint)
      dangling = %{ref | "ref" => String.duplicate("0", 64)}

      assert Evidence.resolve([dangling], [{:checkpoint, checkpoint}]) ==
               {:error, :dangling_evidence_ref}
    end
  end

  defp attested_decision(statement_type, actor, payload, evidence, opts \\ []) do
    context = %Context{
      phase: :tool_request,
      actor: actor,
      trust_level: :medium,
      origin: :agent,
      sink: :tool,
      tool: "agent_handoff"
    }

    decision =
      struct!(Decision,
        verdict: :allowed,
        action: :allow,
        phase: :tool_request,
        risk_level: :medium,
        trust_level: :medium
      )

    base_opts = [
      statement_type: statement_type,
      payload: payload,
      evidence: evidence,
      now: ~U[2026-07-04 10:00:00.000Z],
      ttl_ms: 60_000,
      card_digest: String.duplicate("c", 64),
      peer_trust: :medium
    ]

    Attestation.from_decision(decision, context, Keyword.merge(base_opts, opts))
  end

  defp propagation_chain(count) do
    actors = [
      "spiffe://agents/user-facing",
      "spiffe://agents/router",
      "spiffe://agents/retriever",
      "spiffe://agents/writer",
      "spiffe://agents/auditor"
    ]

    1..count
    |> Enum.map(fn index ->
      actor = Enum.at(actors, rem(index - 1, length(actors)))

      Audit.new_event("agent.boundary", actor, "hop-#{index}", "blocked", %{
        "hop" => "audit:tm12:hop-#{index}"
      })
    end)
    |> Audit.build_chain(@chain_key)
  end

  defp subject_digest(statement, name) do
    statement["subject"]
    |> Enum.find(&(&1["name"] == name))
    |> get_in(["digest", "sha256"])
  end

  defp flip_hex(<<first::binary-size(1), rest::binary>>) do
    flipped = if first == "0", do: "1", else: "0"
    flipped <> rest
  end
end
