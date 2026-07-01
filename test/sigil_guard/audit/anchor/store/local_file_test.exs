defmodule SigilGuard.Audit.Anchor.Store.LocalFileTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Audit
  alias SigilGuard.Audit.Anchor
  alias SigilGuard.Audit.Anchor.Store
  alias SigilGuard.Audit.Anchor.Store.LocalFile
  alias SigilGuard.Audit.Checkpoint
  alias SigilGuard.TestSigner

  @secret_key :crypto.hash(:sha256, "audit anchor store test key")
  @generated_at "2026-01-01T00:00:00.000Z"
  @anchored_at "2026-01-01T00:00:05.000Z"
  @issuer "did:web:anchor-store.example"

  defmodule BadReceiptStore do
    @moduledoc false

    @behaviour SigilGuard.Audit.Anchor.Store

    @impl SigilGuard.Audit.Anchor.Store
    def put(_, _), do: {:ok, :bad_receipt}

    @impl SigilGuard.Audit.Anchor.Store
    def fetch(_, _), do: {:ok, :bad_record}
  end

  describe "put/3, fetch/3, and verify/4" do
    test "persists, fetches, and verifies anchors through the store facade" do
      {checkpoint, anchor} = anchor_fixture()
      path = tmp_path()

      assert {:ok, receipt} =
               Store.put(LocalFile, anchor,
                 path: path,
                 metadata: %{"env" => "test"}
               )

      assert receipt["kind"] == "sigil_guard.audit.anchor.receipt"
      assert receipt["storage"] == "local_file"
      assert receipt["anchor_digest"] == Anchor.digest(anchor)
      assert receipt["metadata"] == %{"env" => "test"}
      assert receipt["uri"] =~ "file://"
      assert File.exists?(path)

      assert {:ok, fetched} = Store.fetch(LocalFile, receipt)
      assert fetched == anchor

      assert {:ok, verified} = Store.verify(LocalFile, receipt, checkpoint)
      assert verified.record == anchor
      assert verified.digest == Anchor.digest(anchor)
    end

    test "fetches anchors by digest when a path is supplied" do
      {_, anchor} = anchor_fixture()
      path = tmp_path()

      assert {:ok, receipt} = Store.put(LocalFile, anchor, path: path)

      assert {:ok, fetched} =
               Store.fetch(LocalFile, receipt["anchor_digest"], path: path)

      assert fetched == anchor
    end

    test "accepts atom-keyed local receipts" do
      {_, anchor} = anchor_fixture()
      path = tmp_path()

      assert {:ok, receipt} = Store.put(LocalFile, anchor, path: path)

      atom_receipt = %{
        uri: receipt["uri"],
        anchor_digest: receipt["anchor_digest"]
      }

      assert {:ok, ^anchor} = Store.fetch(LocalFile, atom_receipt)
    end

    test "rejects receipts with malformed explicit digests before URI fallback" do
      {_, anchor} = anchor_fixture()
      path = tmp_path()

      assert {:ok, receipt} = Store.put(LocalFile, anchor, path: path)

      assert {:error, :missing_digest} =
               Store.fetch(LocalFile, Map.put(receipt, "anchor_digest", false))

      atom_receipt =
        receipt
        |> Map.delete("anchor_digest")
        |> Map.put(:anchor_digest, false)

      assert {:error, :missing_digest} = Store.fetch(LocalFile, atom_receipt)
    end

    test "rejects local receipts when WORM receipts are required" do
      {_, anchor} = anchor_fixture()
      path = tmp_path()

      assert {:error, :worm_required} =
               Store.put(LocalFile, anchor, path: path, require_worm: true)

      refute File.exists?(path)

      assert {:error, :worm_required} =
               LocalFile.put(anchor, path: path, require_worm: true)

      refute File.exists?(path)
    end

    test "rejects malformed receipts returned by store adapters" do
      {_, anchor} = anchor_fixture()

      assert {:error, :invalid_receipt} = Store.put(BadReceiptStore, anchor)
    end

    test "rejects malformed records returned by store adapters" do
      {checkpoint, _} = anchor_fixture()

      assert {:error, :invalid_anchor} = Store.fetch(BadReceiptStore, "ignored")
      assert {:error, :invalid_anchor} = Store.verify(BadReceiptStore, "ignored", checkpoint)
    end
  end

  describe "error handling" do
    test "rejects invalid stores and malformed facade calls" do
      {_, anchor} = anchor_fixture()

      assert {:error, :invalid_store} = Store.put(String, anchor)
      assert {:error, :invalid_store} = Store.fetch(String, "digest")
      assert {:error, :invalid_anchor} = Store.verify(LocalFile, %{}, "bad")
    end

    test "rejects invalid local store inputs" do
      {_, anchor} = anchor_fixture()

      assert {:error, :missing_path} = Store.put(LocalFile, anchor)

      assert {:error, :invalid_anchor} =
               Store.put(LocalFile, %{"kind" => "other"}, path: tmp_path())

      incomplete_anchor = Map.delete(anchor, "anchored_at")
      incomplete_path = tmp_path()

      assert {:error, :missing_anchored_at} =
               Store.put(LocalFile, incomplete_anchor, path: incomplete_path)

      refute File.exists?(incomplete_path)

      invalid_with_atom_fallback =
        anchor
        |> Map.put("kind", false)
        |> Map.put(:kind, "sigil_guard.audit.anchor")

      assert {:error, :invalid_anchor} =
               Store.put(LocalFile, invalid_with_atom_fallback, path: tmp_path())

      assert {:error, :invalid_metadata} =
               Store.put(LocalFile, anchor, path: tmp_path(), metadata: "bad")

      assert {:error, :missing_digest} = Store.fetch(LocalFile, %{}, path: tmp_path())
      assert {:error, :missing_path} = Store.fetch(LocalFile, Anchor.digest(anchor))

      assert {:error, :missing_digest} =
               Store.fetch(LocalFile, String.duplicate("g", 64), path: tmp_path())

      invalid_receipt = %{
        "anchor_digest" => String.duplicate("g", 64),
        "uri" => "file:///tmp/anchors.jsonl##{String.duplicate("g", 64)}"
      }

      assert {:error, :missing_digest} = Store.fetch(LocalFile, invalid_receipt)

      remote_file_receipt = %{
        "anchor_digest" => Anchor.digest(anchor),
        "uri" => "file://example.test/tmp/anchors.jsonl##{Anchor.digest(anchor)}"
      }

      assert {:error, :remote_file_uri} = Store.fetch(LocalFile, remote_file_receipt)
    end

    test "reports missing and corrupt logs" do
      {_, anchor} = anchor_fixture()
      missing_path = tmp_path()

      assert {:error, :not_found} =
               Store.fetch(LocalFile, Anchor.digest(anchor), path: missing_path)

      corrupt_path = tmp_path()
      File.mkdir_p!(Path.dirname(corrupt_path))
      File.write!(corrupt_path, "not json\n")

      assert {:error, :invalid_log} =
               Store.fetch(LocalFile, Anchor.digest(anchor), path: corrupt_path)
    end

    test "detects anchor record digest mismatches inside the log" do
      {_, anchor} = anchor_fixture()
      path = tmp_path()
      digest = Anchor.digest(anchor)
      tampered = Map.put(anchor, "storage", "tampered")

      entry =
        %{"anchor_digest" => digest, "record" => tampered}
        |> Jason.encode!()

      File.mkdir_p!(Path.dirname(path))
      File.write!(path, [entry, ?\n])

      assert {:error, :digest_mismatch} = Store.fetch(LocalFile, digest, path: path)
    end

    test "returns not found when no log entry matches the digest" do
      {_, anchor} = anchor_fixture()
      path = tmp_path()

      assert {:ok, _} = Store.put(LocalFile, anchor, path: path)

      assert {:error, :not_found} =
               Store.fetch(LocalFile, String.duplicate("0", 64), path: path)
    end
  end

  defp anchor_fixture do
    events =
      1..3
      |> Enum.map(&Audit.new_event("test", "alice", "anchor-store-#{&1}", "ok"))
      |> Audit.build_chain(@secret_key)

    {:ok, checkpoint} =
      Checkpoint.create(events,
        chain_id: "chain-a",
        generated_at: @generated_at
      )

    signed_checkpoint =
      Checkpoint.sign(checkpoint, TestSigner, issuer: @issuer, issued_at: @generated_at)

    anchor =
      Anchor.create(signed_checkpoint,
        anchored_at: @anchored_at,
        storage: :local_file,
        uri: "file://anchors.jsonl"
      )

    {signed_checkpoint, anchor}
  end

  defp tmp_path do
    root =
      System.tmp_dir!()
      |> Path.join("sigil_guard_anchor_store_tests")
      |> Path.join("#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf(root) end)

    Path.join(root, "anchors.jsonl")
  end
end
