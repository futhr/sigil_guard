defmodule SigilGuard.TrustBundle.Cache do
  @moduledoc """
  Per-boot ETS snapshot cache for verified trust bundles.

  The cache keeps the last accepted bundle for each bundle id and the
  monotonic rollback floor observed during this boot. It does not verify
  signatures or documents; callers must only pass verified
  `SigilGuard.TrustBundle` structs.
  """

  alias SigilGuard.TrustBundle

  @table :sigil_guard_trust_bundle

  @type put_error :: :sequence_below_floor | :forked_root_chain

  @doc """
  Create the trust-bundle ETS table if it does not already exist.
  """
  @spec ensure_table() :: :ok
  def ensure_table do
    case :ets.whereis(@table) do
      :undefined ->
        try do
          :ets.new(@table, [
            :named_table,
            :public,
            :set,
            read_concurrency: true,
            write_concurrency: true
          ])

          :ok
        rescue
          ArgumentError -> :ok
        end

      _ ->
        :ok
    end
  end

  @doc """
  Return the cached snapshot for a bundle id.
  """
  @spec get(bundle_id :: String.t()) :: {:ok, TrustBundle.t()} | :error
  def get(bundle_id) when is_binary(bundle_id) do
    ensure_table()

    case :ets.lookup(@table, bundle_id) do
      [{^bundle_id, bundle, _}] -> {:ok, bundle}
      [] -> :error
    end
  end

  @doc """
  Accept a verified trust-bundle snapshot if it advances the sequence floor.

  A byte-identical re-put, represented by the same sequence and digest, is
  an accepted no-op. A stale sequence, a bundle below the current floor, or
  a duplicate sequence with a different digest fails with
  `:sequence_below_floor`.
  """
  @spec put(TrustBundle.t()) :: {:ok, TrustBundle.t()} | {:error, put_error()}
  def put(%TrustBundle{bundle_id: bundle_id, sequence: sequence} = bundle)
      when is_binary(bundle_id) and is_integer(sequence) and sequence > 0 do
    ensure_table()

    case :ets.lookup(@table, bundle_id) do
      [] -> put_new(bundle)
      [{^bundle_id, cached, floor}] -> put_existing(bundle, cached, floor)
    end
  end

  @doc """
  Return the current monotonic floor for a bundle id.

  Unknown bundle ids return `0`.
  """
  @spec floor(bundle_id :: String.t()) :: non_neg_integer()
  def floor(bundle_id) when is_binary(bundle_id) do
    ensure_table()

    case :ets.lookup(@table, bundle_id) do
      [{^bundle_id, _, floor}] -> floor
      [] -> 0
    end
  end

  @doc false
  @spec clear() :: :ok
  def clear do
    ensure_table()
    :ets.delete_all_objects(@table)
    :ok
  end

  defp put_new(bundle) do
    floor = accepted_floor(0, bundle)
    :ets.insert(@table, {bundle.bundle_id, bundle, floor})
    {:ok, bundle}
  end

  defp put_existing(bundle, cached, floor) do
    cond do
      same_snapshot?(bundle, cached) ->
        {:ok, cached}

      bundle.sequence <= cached.sequence ->
        {:error, :sequence_below_floor}

      bundle.sequence < floor ->
        {:error, :sequence_below_floor}

      true ->
        accepted = accepted_floor(floor, bundle)
        :ets.insert(@table, {bundle.bundle_id, bundle, accepted})
        {:ok, bundle}
    end
  end

  defp same_snapshot?(bundle, cached) do
    bundle.sequence == cached.sequence and bundle.digest == cached.digest
  end

  defp accepted_floor(floor, bundle) do
    max(floor, max(rollback_floor(bundle), bundle.sequence))
  end

  defp rollback_floor(%TrustBundle{document: %{"rollback_floor" => rollback_floor}})
       when is_binary(rollback_floor) do
    String.to_integer(rollback_floor)
  end

  defp rollback_floor(_), do: 0
end
