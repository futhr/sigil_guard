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
    if store?(store), do: store.put(record, opts), else: {:error, :invalid_store}
  end

  def put(_, _, _), do: {:error, :invalid_store}

  @doc """
  Fetch an anchor record by store receipt or digest.
  """
  @spec fetch(module(), receipt() | String.t(), keyword()) ::
          {:ok, Anchor.t()} | {:error, term()}
  def fetch(store, receipt_or_digest, opts \\ [])

  def fetch(store, receipt_or_digest, opts) when is_atom(store) and is_list(opts) do
    if store?(store), do: store.fetch(receipt_or_digest, opts), else: {:error, :invalid_store}
  end

  def fetch(_, _, _), do: {:error, :invalid_store}

  @doc """
  Fetch an anchor from a store and verify it against a checkpoint.
  """
  @spec verify(module(), receipt() | String.t(), Checkpoint.t(), keyword()) ::
          {:ok, Anchor.verified()} | {:error, term()}
  def verify(store, receipt_or_digest, checkpoint, opts \\ [])

  def verify(store, receipt_or_digest, checkpoint, opts) when is_map(checkpoint) do
    case fetch(store, receipt_or_digest, opts) do
      {:ok, record} -> Anchor.verify(record, checkpoint)
      {:error, reason} -> {:error, reason}
    end
  end

  def verify(_, _, _, _), do: {:error, :invalid_anchor}

  defp store?(store) do
    Code.ensure_loaded?(store) and function_exported?(store, :put, 2) and
      function_exported?(store, :fetch, 2)
  end
end
