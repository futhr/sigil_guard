defmodule SigilGuard.Audit.CheckpointTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Audit
  alias SigilGuard.Audit.Checkpoint
  alias SigilGuard.TestSigner

  @secret_key :crypto.hash(:sha256, "audit checkpoint test key")
  @generated_at "2026-01-01T00:00:00.000Z"
  @issuer "did:web:checkpoint.example"

  test "rejects conflicting signature aliases" do
    {:ok, checkpoint} = Checkpoint.create([])
    signed = Checkpoint.sign(checkpoint, TestSigner, issuer: "issuer")
    opts = [public_key_b64u: TestSigner.public_key_b64u()]

    assert Checkpoint.verify(Map.put(signed, :signature, signed["signature"]), [], opts) ==
             {:error, :invalid_checkpoint}

    invalid = update_in(signed, ["signature"], &Map.put(&1, :issuer, "issuer"))
    assert Checkpoint.verify(invalid, [], opts) == {:error, :invalid_signature_metadata}
  end

  test "malformed events and non-JSON metadata return checked errors" do
    [first] = build_signed_chain(1)

    for events <- [[%{}], [first, %{}], [nil], [first | :bad]] do
      assert Checkpoint.create(events) == {:error, :invalid_events}
    end

    for value <- [
          %{"pid" => self()},
          %{"a" => 2, a: 1},
          %{a: [1 | :bad]},
          %{a: <<255>>},
          %{a: {1, 2}},
          %{self() => 1},
          DateTime.utc_now()
        ] do
      assert Checkpoint.create([], metadata: value) == {:error, :invalid_metadata}
      assert Checkpoint.create([], anchor: value) == {:error, :invalid_anchor_metadata}
    end

    assert Checkpoint.create([], chain_id: self()) == {:error, :invalid_checkpoint}
    assert Checkpoint.create([], generated_at: <<255>>) == {:error, :invalid_checkpoint}
    assert Checkpoint.levels([]) == []
  end

  test "native JSON types survive checkpoint creation and evidence is type-strict" do
    metadata = %{values: [1, 1.0, true, false, nil, "text", %{1 => :value}]}
    {:ok, checkpoint} = Checkpoint.create([], metadata: metadata)
    assert {:ok, _} = Checkpoint.verify(checkpoint, [])
    decoded = Jason.decode!(Checkpoint.canonical_bytes(checkpoint))
    assert decoded["metadata"]["values"] === [1, 1.0, true, false, nil, "text", %{"1" => "value"}]

    assert Checkpoint.verify(Map.put(checkpoint, "version", 1.0), []) ==
             {:error, :invalid_version}

    assert Checkpoint.to_statement(Map.put(checkpoint, "metadata", %{bad: self()})) ==
             {:error, :invalid_checkpoint}

    [event] = build_signed_chain(1)
    {:ok, integer_id} = Checkpoint.create([%{event | id: 1}])
    assert Checkpoint.verify(integer_id, [%{event | id: 1.0}]) == {:error, :checkpoint_mismatch}
  end

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

    test "supports empty chains with a domain-separated root" do
      assert {:ok, root} = Checkpoint.merkle_root([])
      assert {:ok, ^root} = Checkpoint.merkle_root([])
      assert byte_size(root) == 64
    end

    test "rejects non-list event inputs" do
      assert {:error, :invalid_events} = Checkpoint.merkle_root(:bad)
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

    test "creates and verifies empty checkpoints" do
      assert {:ok, checkpoint} = Checkpoint.create([], generated_at: @generated_at)

      assert checkpoint["event_count"] == 0
      assert checkpoint["first_event_id"] == nil
      assert checkpoint["last_event_id"] == nil
      assert checkpoint["first_hmac"] == nil
      assert checkpoint["last_hmac"] == nil
      assert {:ok, verified} = Checkpoint.verify(checkpoint, [])
      assert verified.status == :unsigned
    end

    test "rejects invalid create inputs and invalid continuation anchors" do
      events = build_signed_chain(1)

      assert {:error, :invalid_events} = Checkpoint.create(:bad)
      assert {:error, :invalid_events} = Checkpoint.create(events, :bad)
      assert {:error, :invalid_prev_hmac} = Checkpoint.create([], prev_hmac: 123)
      assert {:error, :invalid_prev_hmac} = Checkpoint.create([], prev_hmac: "")
      assert {:error, :invalid_prev_hmac} = Checkpoint.create(events, prev_hmac: 123)
      assert {:error, :invalid_prev_hmac} = Checkpoint.create(events, prev_hmac: "")
      assert {:error, :invalid_generated_at} = Checkpoint.create(events, generated_at: false)
      assert {:error, :invalid_generated_at} = Checkpoint.create(events, generated_at: "")
      assert {:error, :invalid_metadata} = Checkpoint.create(events, metadata: "bad")
      assert {:error, :invalid_anchor_metadata} = Checkpoint.create(events, anchor: "bad")
    end
  end

  describe "canonical_bytes/1 and digest/1" do
    test "canonical bytes are stable and exclude signature metadata" do
      checkpoint = signed_checkpoint()
      unsigned = Map.delete(checkpoint, "signature")

      assert Checkpoint.canonical_bytes(checkpoint) == Checkpoint.canonical_bytes(unsigned)
      assert Checkpoint.digest(checkpoint) == Checkpoint.digest(unsigned)
    end

    test "canonical bytes normalize atom keys" do
      {:ok, checkpoint} = create_checkpoint(build_signed_chain(1))

      atomized = %{
        kind: checkpoint["kind"],
        version: checkpoint["version"],
        algorithm: checkpoint["algorithm"],
        generated_at: checkpoint["generated_at"],
        chain_id: checkpoint["chain_id"],
        event_count: checkpoint["event_count"],
        prev_hmac: checkpoint["prev_hmac"],
        first_event_id: checkpoint["first_event_id"],
        last_event_id: checkpoint["last_event_id"],
        first_hmac: checkpoint["first_hmac"],
        last_hmac: checkpoint["last_hmac"],
        merkle_root: checkpoint["merkle_root"],
        metadata: checkpoint["metadata"],
        anchor: checkpoint["anchor"]
      }

      assert Checkpoint.canonical_bytes(atomized) == Checkpoint.canonical_bytes(checkpoint)
      assert Checkpoint.digest(atomized) == Checkpoint.digest(checkpoint)
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

    test "verifies signed checkpoints with standard base64 public keys and signatures" do
      events = build_signed_chain(2)
      signed = signed_checkpoint(events)

      signature =
        signed["signature"]["signature"]
        |> Base.url_decode64!(padding: false)
        |> Base.encode64()

      public_key =
        TestSigner.public_key()
        |> Base.encode64()

      reencoded = put_in(signed, ["signature", "signature"], signature)

      assert {:ok, verified} = Checkpoint.verify(reencoded, events, public_key_b64u: public_key)
      assert verified.status == :verified
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

    test "rejects invalid checkpoint and static-field inputs" do
      events = build_signed_chain(1)
      {:ok, checkpoint} = create_checkpoint(events)

      assert {:error, :invalid_checkpoint} = Checkpoint.verify(:bad, events)
      assert {:error, :invalid_checkpoint} = Checkpoint.verify(checkpoint, :bad)

      assert {:error, :invalid_kind} =
               Checkpoint.verify(%{checkpoint | "kind" => "wrong"}, events)

      assert {:error, :invalid_version} =
               Checkpoint.verify(%{checkpoint | "version" => 2}, events)

      assert {:error, :invalid_algorithm} =
               Checkpoint.verify(%{checkpoint | "algorithm" => "sha1"}, events)

      assert {:error, :missing_generated_at} =
               Checkpoint.verify(%{checkpoint | "generated_at" => nil}, events)

      assert {:error, :missing_generated_at} =
               Checkpoint.verify(%{checkpoint | "generated_at" => ""}, events)

      assert {:error, :missing_event_count} =
               Checkpoint.verify(%{checkpoint | "event_count" => "1"}, events)

      assert {:error, :missing_merkle_root} =
               Checkpoint.verify(%{checkpoint | "merkle_root" => nil}, events)

      assert {:error, :missing_merkle_root} =
               Checkpoint.verify(%{checkpoint | "merkle_root" => ""}, events)

      assert {:error, :invalid_prev_hmac} =
               Checkpoint.verify(%{checkpoint | "prev_hmac" => 123}, events)

      assert {:error, :invalid_prev_hmac} =
               Checkpoint.verify(%{checkpoint | "prev_hmac" => ""}, events)
    end

    test "does not let atom fallbacks mask explicit invalid string fields" do
      events = build_signed_chain(1)
      {:ok, checkpoint} = create_checkpoint(events)

      invalid =
        checkpoint
        |> Map.put("kind", false)
        |> Map.put(:kind, "sigil_guard.audit.checkpoint")

      assert {:error, :invalid_kind} = Checkpoint.verify(invalid, events)
    end

    test "rejects uncanonicalizable checkpoint terms without raising" do
      events = build_signed_chain(2)
      signed = signed_checkpoint(events)
      invalid_signed = put_in(signed, ["metadata", "pid"], self())

      assert {:error, :invalid_checkpoint} =
               Checkpoint.verify(invalid_signed, events,
                 public_key_b64u: TestSigner.public_key_b64u()
               )

      invalid_unsigned =
        signed
        |> Map.delete("signature")
        |> put_in(["metadata", "pid"], self())

      assert {:error, :invalid_checkpoint} = Checkpoint.verify(invalid_unsigned, events)
    end

    test "rejects invalid signature metadata" do
      events = build_signed_chain(2)
      signed = signed_checkpoint(events)

      assert {:error, :invalid_signature_metadata} =
               Checkpoint.verify(%{signed | "signature" => "bad"}, events)

      for {field, reason} <- [
            {"issuer", :missing_issuer},
            {"digest", :missing_digest},
            {"signature", :missing_signature}
          ] do
        tampered = update_in(signed, ["signature"], &Map.delete(&1, field))
        assert {:error, ^reason} = Checkpoint.verify(tampered, events)

        empty = put_in(signed, ["signature", field], "")

        assert {:error, ^reason} =
                 Checkpoint.verify(empty, events, public_key_b64u: TestSigner.public_key_b64u())
      end

      unsupported = put_in(signed, ["signature", "algorithm"], "RSA")
      assert {:error, :unsupported_algorithm} = Checkpoint.verify(unsupported, events)
    end

    test "rejects malformed keys and signatures before verification" do
      events = build_signed_chain(2)
      signed = signed_checkpoint(events)

      short_public_key = Base.url_encode64("short", padding: false)
      short_signature = Base.url_encode64("short", padding: false)

      assert {:error, :invalid_base64} =
               Checkpoint.verify(signed, events, public_key_b64u: "not base64!")

      assert {:error, :invalid_public_keys} =
               Checkpoint.verify(signed, events, public_keys: "bad")

      assert {:error, :invalid_key} =
               Checkpoint.verify(signed, events,
                 public_keys: %{@issuer => false},
                 public_key_b64u: TestSigner.public_key_b64u()
               )

      assert {:error, :invalid_key} =
               Checkpoint.verify(signed, events, public_key_b64u: short_public_key)

      short_sig_checkpoint = put_in(signed, ["signature", "signature"], short_signature)

      assert {:error, :invalid_signature} =
               Checkpoint.verify(short_sig_checkpoint, events,
                 public_key_b64u: TestSigner.public_key_b64u()
               )

      bad_sig_checkpoint = put_in(signed, ["signature", "signature"], "not base64!")

      assert {:error, :invalid_base64} =
               Checkpoint.verify(bad_sig_checkpoint, events,
                 public_key_b64u: TestSigner.public_key_b64u()
               )
    end
  end

  describe "to_statement/1" do
    test "builds the checkpoint-state in-toto statement" do
      {:ok, checkpoint} = create_checkpoint(build_signed_chain(3))
      assert {:ok, statement} = Checkpoint.to_statement(checkpoint)

      assert statement["_type"] == "https://in-toto.io/Statement/v1"
      assert statement["predicateType"] == "https://sigilguard.dev/audit-checkpoint-state/v1"

      predicate = statement["predicate"]
      assert predicate["merkle_root"] == checkpoint["merkle_root"]
      assert predicate["generated_at"] == @generated_at
      assert predicate["profile"] == "sigil_guard_agent_trust/v1"
      # tree_size is the event count as a JSON string (attestation growable counter).
      assert predicate["tree_size"] == "3"
      assert predicate["chain_id"] == "chain-a"

      assert statement["subject"] == [
               %{"name" => "checkpoint", "digest" => %{"sha256" => Checkpoint.digest(checkpoint)}}
             ]
    end

    test "the subject digest is identical for the signed and unsigned record" do
      {:ok, unsigned} = create_checkpoint(build_signed_chain(2))
      signed = Checkpoint.sign(unsigned, TestSigner, issuer: @issuer, issued_at: @generated_at)

      {:ok, unsigned_statement} = Checkpoint.to_statement(unsigned)
      {:ok, signed_statement} = Checkpoint.to_statement(signed)

      assert subject_digest(unsigned_statement) == Checkpoint.digest(unsigned)
      assert subject_digest(signed_statement) == subject_digest(unsigned_statement)
    end

    test "omits chain_id when the checkpoint has none" do
      {:ok, checkpoint} = Checkpoint.create(build_signed_chain(1), generated_at: @generated_at)
      assert {:ok, statement} = Checkpoint.to_statement(checkpoint)
      refute Map.has_key?(statement["predicate"], "chain_id")
    end

    test "a malformed or non-checkpoint map fails :invalid_checkpoint" do
      {:ok, checkpoint} = create_checkpoint(build_signed_chain(1))

      assert Checkpoint.to_statement("nope") == {:error, :invalid_checkpoint}
      assert Checkpoint.to_statement(%{}) == {:error, :invalid_checkpoint}
      assert Checkpoint.to_statement(%{"kind" => "other"}) == {:error, :invalid_checkpoint}

      assert Checkpoint.to_statement(Map.delete(checkpoint, "merkle_root")) ==
               {:error, :invalid_checkpoint}

      assert Checkpoint.to_statement(%{checkpoint | "version" => 2}) ==
               {:error, :invalid_checkpoint}
    end
  end

  defp subject_digest(statement), do: hd(statement["subject"])["digest"]["sha256"]

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
