defmodule SigilGuard.Audit.ExportTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Audit
  alias SigilGuard.Audit.Anchor
  alias SigilGuard.Audit.Checkpoint
  alias SigilGuard.Audit.Export
  alias SigilGuard.TestSigner

  @secret_key :crypto.hash(:sha256, "audit export test key")
  @generated_at "2026-01-01T00:00:00.000Z"
  @anchored_at "2026-01-01T00:00:05.000Z"
  @issuer "did:web:export.example"

  test "verifies every supplied evidence object and its complete checkpoint identity" do
    events = SigilGuard.AuditProofFixture.signed_events()
    {:ok, export} = Export.create(events)
    {:ok, statement} = Checkpoint.to_statement(export["checkpoint"])

    altered = [
      Map.put(statement, "_type", "other"),
      Map.put(statement, "predicateType", "other"),
      Map.update!(statement, "subject", &(&1 ++ &1)),
      put_in(statement, ["predicate", "merkle_root"], String.duplicate("0", 64)),
      put_in(statement, ["predicate", "tree_size"], "6"),
      put_in(statement, ["predicate", "chain_id"], "different")
    ]

    for value <- altered do
      {:ok, envelope} = SigilGuard.Attestation.Envelope.sign(Jason.encode!(value), TestSigner)

      assert Export.verify(Map.put(export, "checkpoint_statement", envelope), events) ==
               {:error, :statement_mismatch}
    end

    proof = SigilGuard.AuditProofFixture.consistency_proof(3)
    assert {:ok, _} = Export.verify(Map.put(export, "consistency_proof", proof), events)

    for value <- [
          %{},
          "garbage",
          Map.put(proof, "first_size", 0),
          Map.put(proof, "second_size", 6)
        ] do
      assert Export.verify(Map.put(export, "consistency_proof", value), events) ==
               {:error, :invalid_consistency_proof}
    end

    bad = Map.put(proof, "proof_nodes", [String.duplicate("0", 64)])
    assert {:error, _} = Export.verify(Map.put(export, "consistency_proof", bad), events)
    {:ok, inclusion} = SigilGuard.Audit.Proof.inclusion(events, 0)
    wrong_size = Map.put(inclusion, "tree_size", 6)

    assert Export.verify(Map.put(export, "inclusion_proofs", [wrong_size]), events) ==
             {:error, :out_of_range}

    assert Export.verify(Map.put(export, "version", 1.0), events) == {:error, :invalid_version}
  end

  describe "create/2" do
    test "creates a signed anchored export without raw event bodies" do
      events = build_signed_chain(3)

      assert {:ok, export} = signed_export(events)

      checkpoint = export["checkpoint"]
      anchor = export["anchor"]

      assert export["kind"] == "sigil_guard.audit.export"
      assert export["version"] == 1
      assert export["generated_at"] == @generated_at
      assert checkpoint["signature"]["issuer"] == @issuer
      assert checkpoint["signature"]["algorithm"] == "Ed25519"
      assert anchor["checkpoint_digest"] == Checkpoint.digest(checkpoint)
      assert anchor["storage"] == "s3-object-lock"
      assert anchor["uri"] == "s3://audit-lock/checkpoints/001.json"
      refute inspect(export) =~ "export-action"
    end

    test "creates an unsigned export without an anchor when not requested" do
      events = build_signed_chain(1)

      assert {:ok, export} =
               Export.create(events,
                 chain_id: "chain-a",
                 generated_at: @generated_at
               )

      refute Map.has_key?(export["checkpoint"], "signature")
      assert export["anchor"] == nil
    end

    test "accepts default and map-based anchor options" do
      events = build_signed_chain(1)

      assert {:ok, default_anchor_export} =
               Export.create(events,
                 chain_id: "chain-a",
                 generated_at: @generated_at,
                 anchor: true
               )

      assert default_anchor_export["anchor"]["storage"] == "external"

      assert {:ok, map_anchor_export} =
               Export.create(events,
                 chain_id: "chain-a",
                 generated_at: @generated_at,
                 anchor: %{
                   "anchored_at" => @anchored_at,
                   "storage" => "worm",
                   "uri" => "bench://audit/export",
                   "worm" => true,
                   "metadata" => %{"ignored" => "no"}
                 }
               )

      assert map_anchor_export["anchor"]["anchored_at"] == @anchored_at
      assert map_anchor_export["anchor"]["storage"] == "worm"
      assert map_anchor_export["anchor"]["uri"] == "bench://audit/export"
    end

    test "treats nil anchor option as no external anchor" do
      events = build_signed_chain(1)

      assert {:ok, export} =
               Export.create(events,
                 chain_id: "chain-a",
                 generated_at: @generated_at,
                 anchor: nil
               )

      assert export["anchor"] == nil
    end

    test "rejects invalid event and anchor inputs" do
      assert {:error, :invalid_events} = Export.create("bad")

      assert {:error, :invalid_anchor_options} =
               Export.create(build_signed_chain(1),
                 generated_at: @generated_at,
                 anchor: "bad"
               )

      for {anchor_opts, reason} <- [
            {[anchored_at: ""], :missing_anchored_at},
            {[storage: ""], :missing_storage},
            {[uri: false], :invalid_uri},
            {[worm: "true"], :invalid_worm},
            {[metadata: "bad"], :invalid_metadata},
            {[metadata: %{"pid" => self()}], :invalid_anchor}
          ] do
        assert {:error, ^reason} =
                 Export.create(build_signed_chain(1),
                   generated_at: @generated_at,
                   anchor: anchor_opts
                 )
      end
    end

    test "returns an error when signing is requested without an issuer" do
      events = build_signed_chain(1)

      assert {:error, :missing_issuer} =
               Export.create(events,
                 generated_at: @generated_at,
                 signer: TestSigner
               )
    end
  end

  describe "verify/3" do
    test "verifies signed anchored exports" do
      events = build_signed_chain(3)
      {:ok, export} = signed_export(events)

      assert {:ok, verified} =
               Export.verify(export, events,
                 public_keys: %{@issuer => TestSigner.public_key_b64u()},
                 require_signature: true,
                 require_anchor: true
               )

      assert verified.export == export
      assert verified.checkpoint.status == :verified
      assert verified.checkpoint.issuer == @issuer
      assert verified.anchor.record == export["anchor"]
      assert verified.anchor.digest == Anchor.digest(export["anchor"])
      assert verified.digest == Export.digest(export)
    end

    test "rejects missing anchors when required" do
      events = build_signed_chain(1)

      assert {:ok, export} =
               Export.create(events,
                 chain_id: "chain-a",
                 generated_at: @generated_at
               )

      assert {:error, :missing_anchor} = Export.verify(export, events, require_anchor: true)
    end

    test "verifies unsigned exports when signatures and anchors are optional" do
      events = build_signed_chain(1)

      assert {:ok, export} =
               Export.create(events,
                 chain_id: "chain-a",
                 generated_at: @generated_at
               )

      assert {:ok, verified} = Export.verify(export, events)
      assert verified.checkpoint.status == :unsigned
      assert verified.anchor == nil
    end

    test "detects checkpoint and event mismatches" do
      events = build_signed_chain(2)
      other_events = build_signed_chain(2)
      {:ok, export} = signed_export(events)

      assert {:error, :checkpoint_mismatch} =
               Export.verify(export, other_events,
                 public_keys: %{@issuer => TestSigner.public_key_b64u()}
               )
    end

    test "detects anchor tampering" do
      events = build_signed_chain(2)
      {:ok, export} = signed_export(events)
      tampered = put_in(export, ["anchor", "checkpoint_digest"], String.duplicate("0", 64))

      assert {:error, :anchor_mismatch} =
               Export.verify(tampered, events,
                 public_keys: %{@issuer => TestSigner.public_key_b64u()},
                 require_anchor: true
               )
    end

    test "rejects malformed export packages" do
      events = build_signed_chain(1)
      {:ok, export} = signed_export(events)

      assert {:error, :invalid_export} = Export.verify("bad", events)
      assert {:error, :invalid_export} = Export.verify(export, "bad")
      assert {:error, :invalid_kind} = Export.verify(%{export | "kind" => "other"}, events)
      assert {:error, :invalid_version} = Export.verify(%{export | "version" => 2}, events)

      assert {:error, :missing_generated_at} =
               export
               |> Map.delete("generated_at")
               |> Export.verify(events)

      assert {:error, :missing_checkpoint} =
               export
               |> Map.delete("checkpoint")
               |> Export.verify(events)

      assert {:error, :invalid_anchor} =
               export
               |> Map.put("anchor", "bad")
               |> Export.verify(events, public_keys: %{@issuer => TestSigner.public_key_b64u()})
    end

    test "does not let atom fallbacks mask explicit invalid string fields" do
      events = build_signed_chain(1)
      {:ok, export} = signed_export(events)

      invalid =
        export
        |> Map.put("kind", false)
        |> Map.put(:kind, "sigil_guard.audit.export")

      assert {:error, :invalid_kind} = Export.verify(invalid, events)
    end

    test "rejects uncanonicalizable export terms without raising" do
      events = build_signed_chain(1)
      {:ok, export} = signed_export(events)
      invalid = Map.put(export, "pid", self())

      assert {:error, :invalid_export} =
               Export.verify(invalid, events,
                 public_keys: %{@issuer => TestSigner.public_key_b64u()},
                 require_signature: true,
                 require_anchor: true
               )
    end

    test "validates atom-keyed export packages" do
      events = build_signed_chain(1)
      {:ok, export} = signed_export(events)

      atom_export = %{
        kind: export["kind"],
        version: export["version"],
        generated_at: export["generated_at"],
        checkpoint: export["checkpoint"],
        anchor: export["anchor"]
      }

      assert {:ok, verified} =
               Export.verify(atom_export, events,
                 public_keys: %{@issuer => TestSigner.public_key_b64u()},
                 require_signature: true,
                 require_anchor: true
               )

      assert verified.export == atom_export

      assert {:error, :missing_generated_at} =
               atom_export
               |> Map.put(:generated_at, "")
               |> Export.verify(events)

      assert {:error, :missing_checkpoint} =
               atom_export
               |> Map.put(:checkpoint, nil)
               |> Export.verify(events)
    end
  end

  describe "canonical_bytes/1 and digest/1" do
    test "produces stable canonical export digests" do
      events = build_signed_chain(2)
      {:ok, export} = signed_export(events)

      assert Export.canonical_bytes(export) == Export.canonical_bytes(export)
      assert Export.digest(export) == Export.digest(export)
      assert byte_size(Export.digest(export)) == 64

      changed = put_in(export, ["anchor", "uri"], "s3://audit-lock/checkpoints/002.json")
      assert Export.digest(changed) != Export.digest(export)
    end

    test "canonical bytes normalize atom keys" do
      events = build_signed_chain(1)
      {:ok, export} = signed_export(events)

      atom_export = %{
        kind: export["kind"],
        version: export["version"],
        generated_at: export["generated_at"],
        checkpoint: export["checkpoint"],
        anchor: export["anchor"]
      }

      assert Export.canonical_bytes(atom_export) == Export.canonical_bytes(export)
      assert Export.digest(atom_export) == Export.digest(export)
    end

    test "canonical bytes handle list, atom, and numeric-key values" do
      export = %{
        kind: "sigil_guard.audit.export",
        version: 1,
        generated_at: @generated_at,
        checkpoint: %{
          1 => :numeric_key,
          values: [:ok, true, nil, 12]
        },
        anchor: nil
      }

      decoded =
        export
        |> Export.canonical_bytes()
        |> Jason.decode!()

      assert decoded["checkpoint"]["1"] == "numeric_key"
      assert decoded["checkpoint"]["values"] == ["ok", true, nil, 12]
    end
  end

  describe "signed audit event" do
    test "canonical bytes use exactly the ordered event-hash field list" do
      event = %Audit{
        id: "00000000000000000000000000000001",
        type: "runtime.gate",
        actor: "alice",
        action: "repo_file_write",
        result: "block",
        timestamp: "2026-07-02T12:00:00.000Z",
        metadata: %{"decision" => %{"verdict" => "block"}}
      }

      assert Audit.canonical_bytes(event) ==
               ~s({"action":"repo_file_write","actor":"alice",) <>
                 ~s("id":"00000000000000000000000000000001","result":"block",) <>
                 ~s("timestamp":"2026-07-02T12:00:00.000Z","type":"runtime.gate"})
    end
  end

  describe "create/2 evidence" do
    test "a package without evidence keys stays byte-identical to a 0.2.x export" do
      {:ok, export} = Export.create(build_signed_chain(3), generated_at: @generated_at)

      assert Enum.sort(Map.keys(export)) == ~w(anchor checkpoint generated_at kind version)
      refute Map.has_key?(export, "checkpoint_statement")
      refute Map.has_key?(export, "inclusion_proofs")
      refute Map.has_key?(export, "consistency_proof")
    end

    test "embeds the DSSE statement, inclusion proofs, and consistency proof" do
      {:ok, export} = evidence_export(build_signed_chain(3))

      assert %{"payload" => _, "payloadType" => _, "signatures" => [_ | _]} =
               export["checkpoint_statement"]

      assert length(export["inclusion_proofs"]) == 3
      assert export["consistency_proof"]["first_size"] == 2
    end

    test "a specific inclusion_proofs index list is honored" do
      {:ok, export} =
        Export.create(build_signed_chain(3),
          generated_at: @generated_at,
          inclusion_proofs: [0, 2]
        )

      assert Enum.map(export["inclusion_proofs"], & &1["leaf_index"]) == [0, 2]
      refute Map.has_key?(export, "checkpoint_statement")
    end

    test ":checkpoint_statement without a :signer fails :missing_signer" do
      assert Export.create(build_signed_chain(1), checkpoint_statement: true) ==
               {:error, :missing_signer}
    end

    test "malformed evidence options fail closed" do
      events = build_signed_chain(2)

      assert Export.create(events, inclusion_proofs: "all") ==
               {:error, :invalid_inclusion_proofs}

      assert Export.create(events, consistency_proof: "2") ==
               {:error, :invalid_consistency_proof}

      assert Export.create(events, inclusion_proofs: [9]) == {:error, :out_of_range}
      assert Export.create(events, consistency_proof: 5) == {:error, :out_of_range}
    end
  end

  describe "verify/3 evidence" do
    test "verifies a full evidence package" do
      events = build_signed_chain(3)
      {:ok, export} = evidence_export(events)

      assert {:ok, _} =
               Export.verify(export, events, public_key_b64u: TestSigner.public_key_b64u())
    end

    test "a tampered inclusion proof fails verification" do
      events = build_signed_chain(3)
      {:ok, export} = evidence_export(events)
      [proof | rest] = export["inclusion_proofs"]
      [node | nodes] = proof["audit_path"]
      tampered = Map.put(proof, "audit_path", [flip(node) | nodes])
      broken = Map.put(export, "inclusion_proofs", [tampered | rest])

      assert Export.verify(broken, events, public_key_b64u: TestSigner.public_key_b64u()) ==
               {:error, :proof_verification_failed}
    end

    test "a checkpoint statement for a different checkpoint fails :statement_mismatch" do
      events = build_signed_chain(3)
      {:ok, export} = evidence_export(events)
      {:ok, other} = evidence_export(build_signed_chain(4))
      swapped = Map.put(export, "checkpoint_statement", other["checkpoint_statement"])

      assert Export.verify(swapped, events, public_key_b64u: TestSigner.public_key_b64u()) ==
               {:error, :statement_mismatch}
    end

    test "a malformed checkpoint statement fails :invalid_checkpoint_statement" do
      events = build_signed_chain(3)
      {:ok, export} = evidence_export(events)
      broken = Map.put(export, "checkpoint_statement", %{"payload" => "@@@"})

      assert Export.verify(broken, events, public_key_b64u: TestSigner.public_key_b64u()) ==
               {:error, :invalid_checkpoint_statement}
    end

    test "dropped or reordered events are detected" do
      events = build_signed_chain(4)
      {:ok, export} = evidence_export(events)
      key = [public_key_b64u: TestSigner.public_key_b64u()]

      assert {:error, _} = Export.verify(export, Enum.take(events, 3), key)

      [first, second | rest] = events
      assert {:error, _} = Export.verify(export, [second, first | rest], key)
    end

    test "malformed evidence keys fail closed on verify" do
      events = build_signed_chain(3)
      {:ok, export} = evidence_export(events)
      key = [public_key_b64u: TestSigner.public_key_b64u()]

      # A non-map checkpoint statement.
      assert Export.verify(Map.put(export, "checkpoint_statement", "nope"), events, key) ==
               {:error, :invalid_checkpoint_statement}

      # A statement whose payload carries no subject.
      no_subject = %{"payload" => Base.url_encode64(~s({"a":1}), padding: false)}

      assert Export.verify(Map.put(export, "checkpoint_statement", no_subject), events, key) ==
               {:error, :invalid_checkpoint_statement}

      # A non-list inclusion_proofs value.
      assert Export.verify(Map.put(export, "inclusion_proofs", "nope"), events, key) ==
               {:error, :invalid_inclusion_proofs}

      # A non-map inclusion proof entry.
      assert Export.verify(Map.put(export, "inclusion_proofs", ["nope"]), events, key) ==
               {:error, :invalid_inclusion_proof}

      # An inclusion proof whose leaf index is outside the event list.
      out_of_range = Map.put(hd(export["inclusion_proofs"]), "leaf_index", 99)

      assert Export.verify(Map.put(export, "inclusion_proofs", [out_of_range]), events, key) ==
               {:error, :invalid_inclusion_proof}

      # A non-integer leaf index.
      non_integer = Map.put(hd(export["inclusion_proofs"]), "leaf_index", "0")

      assert Export.verify(Map.put(export, "inclusion_proofs", [non_integer]), events, key) ==
               {:error, :invalid_inclusion_proof}
    end
  end

  defp evidence_export(events) do
    Export.create(events,
      generated_at: @generated_at,
      signer: TestSigner,
      issuer: @issuer,
      issued_at: @generated_at,
      checkpoint_statement: true,
      inclusion_proofs: :all,
      consistency_proof: 2
    )
  end

  defp flip(<<first::binary-size(1), rest::binary>>) do
    replacement = if first == "0", do: "1", else: "0"
    replacement <> rest
  end

  defp signed_export(events) do
    Export.create(events,
      chain_id: "chain-a",
      generated_at: @generated_at,
      checkpoint_anchor: %{"type" => "worm"},
      signer: TestSigner,
      issuer: @issuer,
      issued_at: @generated_at,
      anchor: [
        anchored_at: @anchored_at,
        storage: :"s3-object-lock",
        uri: "s3://audit-lock/checkpoints/001.json"
      ]
    )
  end

  defp build_signed_chain(count) do
    1..count
    |> Enum.map(&Audit.new_event("test", "alice", "export-action-#{&1}", "ok"))
    |> Audit.build_chain(@secret_key)
  end
end
