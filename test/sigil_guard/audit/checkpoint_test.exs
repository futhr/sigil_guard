defmodule SigilGuard.Audit.CheckpointTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Audit
  alias SigilGuard.Audit.Checkpoint
  alias SigilGuard.TestSigner

  @secret_key :crypto.hash(:sha256, "audit checkpoint test key")
  @generated_at "2026-01-01T00:00:00.000Z"
  @issuer "did:web:checkpoint.example"

  describe "merkle_root/1" do
    test "returns a deterministic root over signed event HMACs" do
      events = build_signed_chain(3)

      assert {:ok, root} = Checkpoint.merkle_root(events)
      assert {:ok, ^root} = Checkpoint.merkle_root(events)
      assert byte_size(root) == 64
    end

    test "changes when event order changes" do
      [first, second, third] = build_signed_chain(3)

      assert {:ok, root} = Checkpoint.merkle_root([first, second, third])
      assert {:ok, reordered_root} = Checkpoint.merkle_root([first, third, second])
      assert root != reordered_root
    end

    test "rejects unsigned events" do
      events = [Audit.new_event("test", "alice", "action", "ok")]

      assert {:error, :unsigned_event} = Checkpoint.merkle_root(events)
    end
  end

  describe "create/2" do
    test "creates a portable checkpoint without raw event bodies" do
      events = build_signed_chain(2)

      assert {:ok, checkpoint} =
               Checkpoint.create(events,
                 chain_id: "chain-a",
                 generated_at: @generated_at,
                 metadata: %{"node" => "runner-1"},
                 anchor: %{"type" => "worm", "uri" => "s3://bucket/audit/checkpoint.json"}
               )

      assert checkpoint["kind"] == "sigil_guard.audit.checkpoint"
      assert checkpoint["version"] == 1
      assert checkpoint["algorithm"] == "sha256-merkle-v1"
      assert checkpoint["chain_id"] == "chain-a"
      assert checkpoint["generated_at"] == @generated_at
      assert checkpoint["event_count"] == 2
      assert checkpoint["first_event_id"] == hd(events).id
      assert checkpoint["last_event_id"] == List.last(events).id
      assert checkpoint["first_hmac"] == hd(events).hmac
      assert checkpoint["last_hmac"] == List.last(events).hmac
      assert checkpoint["metadata"] == %{"node" => "runner-1"}
      assert checkpoint["anchor"]["uri"] == "s3://bucket/audit/checkpoint.json"
      refute inspect(checkpoint) =~ hd(events).action
    end

    test "rejects broken chain links" do
      [first, second] = build_signed_chain(2)
      broken = [%{first | prev_hmac: "wrong"}, second]

      assert {:error, :broken_chain} = Checkpoint.create(broken, generated_at: @generated_at)
    end

    test "creates continuation checkpoints from a previous HMAC anchor" do
      [first, second, third] = build_signed_chain(3)

      assert {:ok, checkpoint} =
               Checkpoint.create([second, third],
                 prev_hmac: first.hmac,
                 generated_at: @generated_at
               )

      assert checkpoint["event_count"] == 2
      assert checkpoint["prev_hmac"] == first.hmac
      assert checkpoint["first_event_id"] == second.id
      assert checkpoint["last_event_id"] == third.id
    end
  end

  describe "canonical_bytes/1 and digest/1" do
    test "canonical bytes are stable and exclude signature metadata" do
      checkpoint = signed_checkpoint()
      unsigned = Map.delete(checkpoint, "signature")

      assert Checkpoint.canonical_bytes(checkpoint) == Checkpoint.canonical_bytes(unsigned)
      assert Checkpoint.digest(checkpoint) == Checkpoint.digest(unsigned)
    end
  end

  describe "sign/3 and verify/3" do
    test "signs and verifies a checkpoint with Ed25519 provenance" do
      events = build_signed_chain(3)
      {:ok, checkpoint} = create_checkpoint(events)
      signed = Checkpoint.sign(checkpoint, TestSigner, issuer: @issuer, issued_at: @generated_at)

      assert signed["signature"]["issuer"] == @issuer
      assert signed["signature"]["algorithm"] == "Ed25519"
      assert signed["signature"]["digest"] == Checkpoint.digest(signed)

      assert {:ok, verified} =
               Checkpoint.verify(signed, events,
                 public_keys: %{@issuer => TestSigner.public_key_b64u()}
               )

      assert verified.status == :verified
      assert verified.issuer == @issuer
      assert verified.digest == Checkpoint.digest(signed)
    end

    test "verifies unsigned checkpoints unless signatures are required" do
      events = build_signed_chain(1)
      {:ok, checkpoint} = create_checkpoint(events)

      assert {:ok, verified} = Checkpoint.verify(checkpoint, events)
      assert verified.status == :unsigned
      assert verified.issuer == nil

      assert {:error, :unsigned_checkpoint} =
               Checkpoint.verify(checkpoint, events, require_signature: true)
    end

    test "detects event/checkpoint mismatch" do
      events = build_signed_chain(2)
      other_events = build_signed_chain(2)
      {:ok, checkpoint} = create_checkpoint(events)

      assert {:error, :checkpoint_mismatch} = Checkpoint.verify(checkpoint, other_events)
    end

    test "detects signature digest mismatch" do
      events = build_signed_chain(2)
      signed = signed_checkpoint(events)

      tampered =
        update_in(signed, ["signature", "digest"], fn _ ->
          String.duplicate("0", 64)
        end)

      assert {:error, :digest_mismatch} =
               Checkpoint.verify(tampered, events, public_key_b64u: TestSigner.public_key_b64u())
    end

    test "detects invalid signatures after checkpoint tampering" do
      events = build_signed_chain(2)
      signed = signed_checkpoint(events)
      tampered = %{signed | "chain_id" => "different-chain"}
      tampered = put_in(tampered, ["signature", "digest"], Checkpoint.digest(tampered))

      assert {:error, :invalid_signature} =
               Checkpoint.verify(tampered, events,
                 public_keys: %{@issuer => TestSigner.public_key_b64u()}
               )
    end

    test "rejects signed checkpoints from unknown issuers" do
      events = build_signed_chain(2)
      signed = signed_checkpoint(events)

      assert {:error, :unknown_issuer} = Checkpoint.verify(signed, events)
    end
  end

  defp signed_checkpoint(events \\ build_signed_chain(2)) do
    {:ok, checkpoint} = create_checkpoint(events)
    Checkpoint.sign(checkpoint, TestSigner, issuer: @issuer, issued_at: @generated_at)
  end

  defp create_checkpoint(events) do
    Checkpoint.create(events,
      chain_id: "chain-a",
      generated_at: @generated_at,
      metadata: %{"node" => "runner-1"}
    )
  end

  defp build_signed_chain(count) do
    1..count
    |> Enum.map(&Audit.new_event("test", "alice", "action#{&1}", "ok"))
    |> Audit.build_chain(@secret_key)
  end
end
