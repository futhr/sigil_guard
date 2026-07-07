defmodule SigilGuard.Audit.Anchor.StoreTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Audit.Anchor
  alias SigilGuard.Audit.Anchor.Store
  alias SigilGuard.Audit.Checkpoint

  defmodule BadReceiptStore do
    @moduledoc false

    @behaviour Store

    @impl Store
    def put(_, _), do: {:ok, :not_a_receipt}

    @impl Store
    def fetch(_, _), do: {:ok, :not_an_anchor}
  end

  defmodule MissingFetchStore do
    @moduledoc false

    def put(_, _), do: {:ok, %{}}
  end

  defmodule MemoryStore do
    @moduledoc false

    @behaviour Store

    @impl Store
    def put(anchor, opts) do
      receipt =
        %{
          anchor_digest: Anchor.digest(anchor),
          record: anchor,
          storage: Keyword.get(opts, :storage, :memory),
          uri: Keyword.get(opts, :uri, "memory://anchors/1"),
          worm: Keyword.get(opts, :worm, true)
        }

      {:ok, receipt}
    end

    @impl Store
    def fetch(%{record: record}, _), do: {:ok, record}
    def fetch(:wrong_kind, _), do: {:ok, %{"kind" => "wrong"}}
    def fetch(:bad_record, _), do: {:ok, "not an anchor"}
    def fetch(:missing, _), do: {:error, :not_found}
  end

  defmodule UnknownResultStore do
    @moduledoc false

    @behaviour Store

    @impl Store
    def put(_, _), do: :ok

    @impl Store
    def fetch(_, _), do: :ok
  end

  test "rejects invalid store modules and malformed inputs" do
    assert Store.put(MissingFetchStore, %{}) == {:error, :invalid_store}
    assert Store.put("store", %{}) == {:error, :invalid_store}
    assert Store.fetch(MissingFetchStore, %{}) == {:error, :invalid_store}
    assert Store.verify(MissingFetchStore, %{}, %{}) == {:error, :invalid_store}
    assert Store.verify(BadReceiptStore, %{}, :bad_checkpoint) == {:error, :invalid_anchor}
    assert Store.fetch(MemoryStore, %{}, :bad_opts) == {:error, :invalid_store}
    assert Store.put(MemoryStore, %{}, :bad_opts) == {:error, :invalid_store}
    assert Store.fetch("store", %{}) == {:error, :invalid_store}
  end

  test "rejects malformed store callback results" do
    assert Store.put(BadReceiptStore, %{}) == {:error, :invalid_receipt}
    assert Store.fetch(BadReceiptStore, %{}) == {:error, :invalid_anchor}
    assert Store.fetch(MemoryStore, :wrong_kind) == {:error, :invalid_anchor}
    assert Store.fetch(MemoryStore, :bad_record) == {:error, :invalid_anchor}
    assert Store.verify(MemoryStore, :missing, checkpoint()) == {:error, :not_found}
  end

  test "enforces WORM receipts when requested" do
    anchor = anchor()

    assert {:ok, receipt} = Store.put(MemoryStore, anchor, require_worm: true)
    assert receipt.worm == true

    assert Store.put(MemoryStore, anchor, require_worm: true, worm: false) ==
             {:error, :worm_required}
  end

  test "fetches and verifies anchors from receipt records" do
    checkpoint = checkpoint()
    anchor = anchor(checkpoint)

    assert {:ok, receipt} =
             Store.put(MemoryStore, anchor,
               storage: :"s3-object-lock",
               uri: "s3://audit-lock/checkpoints/1.json"
             )

    assert {:ok, ^anchor} = Store.fetch(MemoryStore, receipt)
    assert {:ok, verified} = Store.verify(MemoryStore, receipt, checkpoint)
    assert verified.record == anchor
    assert verified.digest == Anchor.digest(anchor)
  end

  test "emits outcome and storage telemetry for store operations" do
    event = [:sigil_guard, :audit, :anchor_store, :put, :stop]
    handler = "anchor-store-test-#{System.unique_integer([:positive])}"
    parent = self()

    :telemetry.attach(
      handler,
      event,
      fn ^event, _, metadata, _ ->
        send(parent, {:anchor_store, metadata})
      end,
      nil
    )

    try do
      assert {:ok, _} =
               Store.put(MemoryStore, anchor(),
                 storage: :"s3-object-lock",
                 uri: "s3://audit-lock/checkpoints/1.json"
               )

      assert_receive {:anchor_store, metadata}
      assert metadata.outcome == :ok
      assert metadata.anchor_storage == "memory"
      assert metadata.anchor_uri_scheme == "memory"
      assert is_binary(metadata.anchor_digest)
    after
      :telemetry.detach(handler)
    end
  end

  test "emits unknown telemetry outcome for malformed callback tuples" do
    event = [:sigil_guard, :audit, :anchor_store, :put, :stop]
    handler = "anchor-store-unknown-test-#{System.unique_integer([:positive])}"
    parent = self()

    :telemetry.attach(
      handler,
      event,
      fn ^event, _, metadata, _ ->
        send(parent, {:anchor_store, metadata})
      end,
      nil
    )

    try do
      assert Store.put(UnknownResultStore, anchor()) == :ok

      assert_receive {:anchor_store, metadata}
      assert metadata.outcome == :unknown
      refute Map.has_key?(metadata, :anchor_digest)
    after
      :telemetry.detach(handler)
    end
  end

  defp anchor(checkpoint \\ checkpoint()) do
    Anchor.create(checkpoint,
      anchored_at: "2026-01-01T00:00:05.000Z",
      storage: :memory,
      uri: "memory://anchors/1"
    )
  end

  defp checkpoint do
    {:ok, checkpoint} = Checkpoint.create([], generated_at: "2026-01-01T00:00:00.000Z")
    checkpoint
  end
end
