defmodule SigilGuard.Audit.AnchorTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Audit
  alias SigilGuard.Audit.Anchor
  alias SigilGuard.Audit.Checkpoint
  alias SigilGuard.TestSigner

  @secret_key :crypto.hash(:sha256, "audit anchor test key")
  @generated_at "2026-01-01T00:00:00.000Z"
  @anchored_at "2026-01-01T00:00:05.000Z"
  @issuer "did:web:anchor.example"

  describe "create/2" do
    test "creates a compact external WORM anchor record" do
      {checkpoint, _} = signed_checkpoint()

      anchor =
        Anchor.create(checkpoint,
          anchored_at: @anchored_at,
          storage: :"s3-object-lock",
          uri: "s3://audit-lock/checkpoints/001.json",
          metadata: %{"region" => "eu-north-1"}
        )

      assert anchor["kind"] == "sigil_guard.audit.anchor"
      assert anchor["version"] == 1
      assert anchor["anchored_at"] == @anchored_at
      assert anchor["checkpoint_digest"] == Checkpoint.digest(checkpoint)
      assert anchor["checkpoint_kind"] == checkpoint["kind"]
      assert anchor["chain_id"] == checkpoint["chain_id"]
      assert anchor["event_count"] == checkpoint["event_count"]
      assert anchor["last_event_id"] == checkpoint["last_event_id"]
      assert anchor["last_hmac"] == checkpoint["last_hmac"]
      assert anchor["merkle_root"] == checkpoint["merkle_root"]
      assert anchor["storage"] == "s3-object-lock"
      assert anchor["uri"] == "s3://audit-lock/checkpoints/001.json"
      assert anchor["worm"]
      assert anchor["metadata"] == %{"region" => "eu-north-1"}
    end
  end

  describe "canonical_bytes/1 and digest/1" do
    test "canonical anchor bytes are stable across map ordering and atom keys" do
      {checkpoint, _} = signed_checkpoint()
      anchor = Anchor.create(checkpoint, anchored_at: @anchored_at)

      atom_anchor =
        anchor
        |> Enum.map(fn {key, value} -> {String.to_existing_atom(key), value} end)
        |> Map.new()

      assert Anchor.canonical_bytes(anchor) == Anchor.canonical_bytes(atom_anchor)
      assert Anchor.digest(anchor) == Anchor.digest(atom_anchor)
      assert byte_size(Anchor.digest(anchor)) == 64
    end
  end

  describe "validate/1" do
    test "validates standalone anchor structure before checkpoint comparison" do
      {checkpoint, _} = signed_checkpoint()
      anchor = Anchor.create(checkpoint, anchored_at: @anchored_at)

      assert :ok = Anchor.validate(anchor)
      assert {:error, :invalid_anchor} = Anchor.validate("bad")
      assert {:error, :invalid_kind} = Anchor.validate(%{"kind" => "other"})

      assert {:error, :missing_anchored_at} =
               anchor
               |> Map.delete("anchored_at")
               |> Anchor.validate()

      assert {:error, :invalid_version} =
               anchor
               |> Map.put("version", 2)
               |> Anchor.validate()

      assert {:error, :missing_event_count} =
               anchor
               |> Map.put("event_count", -1)
               |> Anchor.validate()

      assert {:error, :missing_merkle_root} =
               anchor
               |> Map.put("merkle_root", "")
               |> Anchor.validate()

      assert {:error, :missing_storage} =
               anchor
               |> Map.put("storage", "")
               |> Anchor.validate()

      assert {:error, :invalid_uri} =
               anchor
               |> Map.put("uri", false)
               |> Anchor.validate()

      assert {:error, :invalid_worm} =
               anchor
               |> Map.put("worm", "true")
               |> Anchor.validate()

      assert {:error, :invalid_metadata} =
               anchor
               |> Map.put("metadata", false)
               |> Anchor.validate()
    end
  end

  describe "verify/2" do
    test "verifies an anchor against its checkpoint" do
      {checkpoint, _} = signed_checkpoint()
      anchor = Anchor.create(checkpoint, anchored_at: @anchored_at)

      assert {:ok, verified} = Anchor.verify(anchor, checkpoint)
      assert verified.record == anchor
      assert verified.digest == Anchor.digest(anchor)
    end

    test "detects checkpoint digest mismatch" do
      {checkpoint, _} = signed_checkpoint()

      anchor = %{
        Anchor.create(checkpoint, anchored_at: @anchored_at)
        | "checkpoint_digest" => "x"
      }

      assert {:error, :anchor_mismatch} = Anchor.verify(anchor, checkpoint)
    end

    test "detects checkpoint summary mismatch" do
      {checkpoint, _} = signed_checkpoint()
      anchor = Anchor.create(checkpoint, anchored_at: @anchored_at)

      tampered =
        checkpoint
        |> Map.put("last_event_id", "different")
        |> put_in(
          ["signature", "digest"],
          Checkpoint.digest(Map.put(checkpoint, "last_event_id", "different"))
        )

      assert {:error, :anchor_mismatch} = Anchor.verify(anchor, tampered)
    end

    test "rejects malformed anchor records" do
      {checkpoint, _} = signed_checkpoint()

      assert {:error, :invalid_anchor} = Anchor.verify("bad", checkpoint)
      assert {:error, :invalid_kind} = Anchor.verify(%{"kind" => "other"}, checkpoint)

      missing_digest =
        checkpoint
        |> Anchor.create(anchored_at: @anchored_at)
        |> Map.delete("checkpoint_digest")

      assert {:error, :missing_checkpoint_digest} = Anchor.verify(missing_digest, checkpoint)
    end

    test "does not let atom fallbacks mask explicit invalid string fields" do
      {checkpoint, _} = signed_checkpoint()

      invalid =
        checkpoint
        |> Anchor.create(anchored_at: @anchored_at)
        |> Map.put("kind", false)
        |> Map.put(:kind, "sigil_guard.audit.anchor")

      assert {:error, :invalid_kind} = Anchor.verify(invalid, checkpoint)

      invalid_worm =
        checkpoint
        |> Anchor.create(anchored_at: @anchored_at)
        |> Map.put("worm", "true")
        |> Map.put(:worm, true)

      assert {:error, :invalid_worm} = Anchor.verify(invalid_worm, checkpoint)
    end
  end

  defp signed_checkpoint do
    events =
      1..3
      |> Enum.map(&Audit.new_event("test", "alice", "anchor#{&1}", "ok"))
      |> Audit.build_chain(@secret_key)

    {:ok, checkpoint} =
      Checkpoint.create(events,
        chain_id: "chain-a",
        generated_at: @generated_at
      )

    {Checkpoint.sign(checkpoint, TestSigner, issuer: @issuer, issued_at: @generated_at), events}
  end
end
