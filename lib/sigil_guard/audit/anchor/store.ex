defmodule SigilGuard.Audit.Anchor.Store do
  @moduledoc """
  Behaviour and facade for external audit anchor storage.

  Anchor records are compact, JSON-compatible checkpoint summaries. A store
  persists those records somewhere outside the local audit chain, such as an
  append-only file, WORM bucket, transparency log, or database table. Stores
  should return a receipt that lets callers fetch the same anchor later.
  """

  alias SigilGuard.Audit.Anchor
  alias SigilGuard.Audit.Checkpoint
  alias SigilGuard.Telemetry

  @atom_fields %{
    "anchor_digest" => :anchor_digest,
    "kind" => :kind,
    "storage" => :storage,
    "uri" => :uri
  }
  @anchor_kind "sigil_guard.audit.anchor"

  @typedoc "Store-specific persistence receipt for an anchor record."
  @type receipt :: %{required(String.t()) => term()}

  @callback put(Anchor.t(), keyword()) :: {:ok, receipt()} | {:error, term()}
  @callback fetch(receipt() | String.t(), keyword()) :: {:ok, Anchor.t()} | {:error, term()}

  @doc """
  Persist an anchor record through a store module.
  """
  @spec put(module(), Anchor.t(), keyword()) :: {:ok, receipt()} | {:error, term()}
  def put(store, record, opts \\ [])

  def put(store, record, opts) when is_atom(store) and is_map(record) and is_list(opts) do
    span(:put, store, fn ->
      if store?(store), do: store.put(record, opts), else: {:error, :invalid_store}
    end)
  end

  def put(_, _, _), do: {:error, :invalid_store}

  @doc """
  Fetch an anchor record by store receipt or digest.
  """
  @spec fetch(module(), receipt() | String.t(), keyword()) ::
          {:ok, Anchor.t()} | {:error, term()}
  def fetch(store, receipt_or_digest, opts \\ [])

  def fetch(store, receipt_or_digest, opts) when is_atom(store) and is_list(opts) do
    span(:fetch, store, fn ->
      if store?(store), do: store.fetch(receipt_or_digest, opts), else: {:error, :invalid_store}
    end)
  end

  def fetch(_, _, _), do: {:error, :invalid_store}

  @doc """
  Fetch an anchor from a store and verify it against a checkpoint.
  """
  @spec verify(module(), receipt() | String.t(), Checkpoint.t(), keyword()) ::
          {:ok, Anchor.verified()} | {:error, term()}
  def verify(store, receipt_or_digest, checkpoint, opts \\ [])

  def verify(store, receipt_or_digest, checkpoint, opts) when is_map(checkpoint) do
    span(:verify, store, fn ->
      case fetch(store, receipt_or_digest, opts) do
        {:ok, record} -> Anchor.verify(record, checkpoint)
        {:error, reason} -> {:error, reason}
      end
    end)
  end

  def verify(_, _, _, _), do: {:error, :invalid_anchor}

  defp span(operation, store, fun) do
    metadata = %{anchor_store: inspect(store)}

    Telemetry.span([:sigil_guard, :audit, :anchor_store, operation], metadata, fn ->
      result = fun.()
      {result, Map.merge(metadata, result_metadata(result))}
    end)
  end

  defp result_metadata({:ok, receipt_or_record}) do
    receipt_or_record
    |> digest_metadata()
    |> Map.merge(storage_metadata(receipt_or_record))
    |> Map.put(:outcome, :ok)
  end

  defp result_metadata({:error, reason}) do
    %{outcome: :error, error_reason: reason}
  end

  defp result_metadata(_), do: %{outcome: :unknown}

  defp digest_metadata(%{digest: digest}) when is_binary(digest), do: %{anchor_digest: digest}

  defp digest_metadata(%{} = map) do
    case {field(map, "anchor_digest"), field(map, "kind")} do
      {digest, _} when is_binary(digest) -> %{anchor_digest: digest}
      {_, @anchor_kind} -> %{anchor_digest: Anchor.digest(map)}
      _ -> %{}
    end
  end

  defp digest_metadata(_), do: %{}

  defp storage_metadata(%{record: record}) when is_map(record), do: storage_metadata(record)

  defp storage_metadata(%{} = map) do
    %{}
    |> maybe_put(:anchor_storage, field(map, "storage"))
    |> maybe_put(:anchor_uri_scheme, uri_scheme(field(map, "uri")))
  end

  defp storage_metadata(_), do: %{}

  defp uri_scheme(uri) when is_binary(uri), do: URI.parse(uri).scheme
  defp uri_scheme(_), do: nil

  defp field(map, key) when is_map(map),
    do: Map.get(map, key) || Map.get(map, Map.fetch!(@atom_fields, key))

  defp maybe_put(map, _, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp store?(store) do
    Code.ensure_loaded?(store) and function_exported?(store, :put, 2) and
      function_exported?(store, :fetch, 2)
  end
end
