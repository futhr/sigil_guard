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
