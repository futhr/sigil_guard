defmodule SigilGuard.Audit.WitnessTest do
  use ExUnit.Case, async: true

  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Audit.Checkpoint
  alias SigilGuard.Audit.Proof
  alias SigilGuard.Audit.Witness
  alias SigilGuard.AuditProofFixture, as: Fixture
  alias SigilGuard.Canonical.JCS

  defmodule Witness1 do
    @moduledoc false
    @behaviour SigilGuard.Signer
    @seed for b <- 0x41..0x60, into: <<>>, do: <<b>>

    @impl SigilGuard.Signer
    def sign(message) do
      {_, private_key} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])
    end

    @impl SigilGuard.Signer
    def public_key do
      {public_key, _} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      public_key
    end
  end

  defmodule Witness2 do
    @moduledoc false
    @behaviour SigilGuard.Signer
    @seed for b <- 0x61..0x80, into: <<>>, do: <<b>>

    @impl SigilGuard.Signer
    def sign(message) do
      {_, private_key} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])
    end

    @impl SigilGuard.Signer
    def public_key do
      {public_key, _} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      public_key
    end
  end

  defmodule BadSigner do
    @moduledoc false
    def sign(_), do: "too-short"
    def public_key, do: "not-a-key"
  end

  setup do
    {:ok, payload} = JCS.encode(Fixture.statement())
    {:ok, envelope} = Envelope.sign(payload, Fixture.signer())

    keys = %{
      Envelope.keyid(Witness1.public_key()) => Witness1.public_key(),
      Envelope.keyid(Witness2.public_key()) => Witness2.public_key()
    }

    %{envelope: envelope, keys: keys}
  end

  describe "cosign/3" do
    test "appends a witness signature without modifying the payload", ctx do
      assert {:ok, cosigned} = Witness.cosign(ctx.envelope, Witness1)

      assert cosigned["payload"] == ctx.envelope["payload"]
      assert length(cosigned["signatures"]) == length(ctx.envelope["signatures"]) + 1
      # The operator signature entry is preserved verbatim.
      assert hd(cosigned["signatures"]) == hd(ctx.envelope["signatures"])
    end

    test "multiple witnesses append distinct entries and all verify", ctx do
      {:ok, one} = Witness.cosign(ctx.envelope, Witness1)
      assert {:ok, two} = Witness.cosign(one, Witness2)

      assert length(two["signatures"]) == 3

      assert Witness.verify_threshold(two, ctx.keys, 2) ==
               {:ok, %{verified_keyids: sorted(ctx.keys)}}
    end

    test "a key id already present fails :duplicate_keyid", ctx do
      {:ok, cosigned} = Witness.cosign(ctx.envelope, Witness1)
      assert Witness.cosign(cosigned, Witness1) == {:error, :duplicate_keyid}
    end

    test "a signer that cannot produce an Ed25519 signature fails :invalid_signer", ctx do
      assert Witness.cosign(ctx.envelope, BadSigner) == {:error, :invalid_signer}
    end

    test "a non-map envelope fails :invalid_envelope" do
      assert Witness.cosign("nope", Witness1) == {:error, :invalid_envelope}
    end
  end

  describe "cosign/3 with :previous consistency gate" do
    setup do
      events = Fixture.signed_events()

      {:ok, cp3} =
        Checkpoint.create(Enum.take(events, 3), generated_at: "2026-07-02T12:00:03.000Z")

      {:ok, statement3} = Checkpoint.to_statement(cp3)
      %{events: events, statement3: statement3}
    end

    test "cosigns when the consistency proof from the prior checkpoint verifies", ctx do
      {:ok, proof} = Proof.consistency(ctx.events, 3)
      previous = %{statement: ctx.statement3, consistency_proof: proof}

      assert {:ok, cosigned} = Witness.cosign(fresh_envelope(), Witness1, previous: previous)
      assert length(cosigned["signatures"]) == 2
    end

    test "refuses with :inconsistent_tree when the prior checkpoint is forked", ctx do
      # A 4-to-5 proof does not connect the size-3 root to the size-5 root.
      {:ok, wrong_proof} = Proof.consistency(ctx.events, 4)
      previous = %{statement: ctx.statement3, consistency_proof: wrong_proof}

      assert Witness.cosign(fresh_envelope(), Witness1, previous: previous) ==
               {:error, :inconsistent_tree}
    end

    test "refuses with the proof error for an out-of-range previous", ctx do
      {:ok, proof} = Proof.consistency(ctx.events, 3)
      # first_size 0 is out of range regardless of the roots.
      broken = Map.put(proof, "first_size", 0)
      previous = %{statement: ctx.statement3, consistency_proof: broken}

      assert Witness.cosign(fresh_envelope(), Witness1, previous: previous) ==
               {:error, :out_of_range}
    end

    test "a malformed :previous fails :invalid_proof" do
      assert Witness.cosign(fresh_envelope(), Witness1, previous: %{}) == {:error, :invalid_proof}

      assert Witness.cosign(fresh_envelope(), Witness1, previous: :bad) ==
               {:error, :invalid_proof}
    end

    test "a previous statement missing its merkle root fails :invalid_proof", ctx do
      {:ok, proof} = Proof.consistency(ctx.events, 3)
      previous = %{statement: %{"predicate" => %{}}, consistency_proof: proof}

      assert Witness.cosign(fresh_envelope(), Witness1, previous: previous) ==
               {:error, :invalid_proof}
    end

    test "an unreadable current envelope payload fails :invalid_envelope", ctx do
      {:ok, proof} = Proof.consistency(ctx.events, 3)
      previous = %{statement: ctx.statement3, consistency_proof: proof}
      broken = Map.put(fresh_envelope(), "payload", "not*base64*url")
      assert Witness.cosign(broken, Witness1, previous: previous) == {:error, :invalid_envelope}
    end
  end

  describe "verify_threshold/3" do
    setup ctx do
      {:ok, one} = Witness.cosign(ctx.envelope, Witness1)
      {:ok, two} = Witness.cosign(one, Witness2)
      %{cosigned: two}
    end

    test "returns all verified keyids (not just the threshold) when met", ctx do
      # Both witnesses verify, so a lower threshold still lists every verified id.
      assert Witness.verify_threshold(ctx.cosigned, ctx.keys, 2) ==
               {:ok, %{verified_keyids: sorted(ctx.keys)}}

      assert Witness.verify_threshold(ctx.cosigned, ctx.keys, 1) ==
               {:ok, %{verified_keyids: sorted(ctx.keys)}}
    end

    test "fails :witness_threshold_not_met below the threshold", ctx do
      assert Witness.verify_threshold(ctx.cosigned, ctx.keys, 3) ==
               {:error, :witness_threshold_not_met}
    end

    test "a tampered witness signature is not counted", ctx do
      tampered = tamper_signature(ctx.cosigned, Witness1)

      # Only Witness2 still verifies, so a threshold of 2 is no longer met.
      assert Witness.verify_threshold(tampered, ctx.keys, 2) ==
               {:error, :witness_threshold_not_met}

      assert {:ok, %{verified_keyids: [only]}} = Witness.verify_threshold(tampered, ctx.keys, 1)
      assert only == Envelope.keyid(Witness2.public_key())
    end

    test "an unresolved witness key is tolerated and not counted", ctx do
      {:ok, one} = Witness.cosign(ctx.envelope, Witness1)
      assert Witness.verify_threshold(one, ctx.keys, 2) == {:error, :witness_threshold_not_met}

      assert {:ok, %{verified_keyids: [only]}} = Witness.verify_threshold(one, ctx.keys, 1)
      assert only == Envelope.keyid(Witness1.public_key())
    end

    test "a duplicate keyid in the envelope surfaces :duplicate_keyid", ctx do
      [op, w1 | rest] = ctx.cosigned["signatures"]
      duplicated = Map.put(ctx.cosigned, "signatures", [op, w1, w1 | rest])

      assert Witness.verify_threshold(duplicated, ctx.keys, 1) == {:error, :duplicate_keyid}
    end

    test "a structurally invalid envelope surfaces the DSSE error", ctx do
      bad_type = Map.put(ctx.cosigned, "payloadType", "application/json")
      assert Witness.verify_threshold(bad_type, ctx.keys, 1) == {:error, :invalid_payload_type}
    end

    test "an operator-only envelope meets no witness threshold", ctx do
      # No witness keyid resolves, but the envelope is otherwise valid.
      assert Witness.verify_threshold(ctx.envelope, ctx.keys, 1) ==
               {:error, :witness_threshold_not_met}
    end
  end

  defp fresh_envelope do
    {:ok, payload} = JCS.encode(Fixture.statement())
    {:ok, envelope} = Envelope.sign(payload, Fixture.signer())
    envelope
  end

  defp sorted(keys), do: Enum.sort(Map.keys(keys))

  defp tamper_signature(envelope, signer) do
    keyid = Envelope.keyid(signer.public_key())

    signatures =
      Enum.map(envelope["signatures"], fn entry ->
        if entry["keyid"] == keyid do
          Map.put(entry, "sig", flip_first(entry["sig"]))
        else
          entry
        end
      end)

    Map.put(envelope, "signatures", signatures)
  end

  defp flip_first(<<first::binary-size(1), rest::binary>>) do
    replacement = if first == "A", do: "B", else: "A"
    replacement <> rest
  end
end
