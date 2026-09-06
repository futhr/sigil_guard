defmodule SigilGuard.ReplayStore do
  @moduledoc """
  ETS-backed replay protection for signed SIGIL envelopes and confirmation tokens.

  The store records `{identity, nonce}` pairs for a bounded TTL. It is kept
  separate from signature verification so callers can choose stateless
  verification for compatibility tests and enable replay protection at MCP,
  approval, or API trust boundaries. Only fixed-size SHA-256 fingerprints of
  identities and nonces are retained. Capacity defaults to 100,000 live claims;
  `check_and_put/4` can enforce a lower capacity and returns
  `:replay_capacity_exceeded` without evicting live entries.
  """

  @table :sigil_guard_replay
  @prune_key {:sigil_guard_replay_store, :meta, :last_prune}
  @prune_interval_ms 60_000
  @capacity_key {__MODULE__, :meta, :entries}

  @doc "Create the replay table if it does not already exist."
  @spec ensure_table() :: :ok
  def ensure_table do
    if :ets.whereis(@table) == :undefined do
      try do
        :ets.new(@table, [
          :named_table,
          :public,
          :set,
          read_concurrency: true,
          write_concurrency: true
        ])
      rescue
        ArgumentError -> :ok
      end
    end

    :ets.insert_new(
      @table,
      {@prune_key, System.monotonic_time(:millisecond) - @prune_interval_ms}
    )

    :ets.insert_new(@table, {@capacity_key, 0})
    :ok
  end

  @doc """
  Record a nonce if it has not been seen within its TTL.

  Returns `{:error, :replay_detected}` when the same identity/nonce pair is
  still live.
  """
  @spec check_and_put(String.t(), String.t(), pos_integer(), pos_integer()) ::
          :ok | {:error, :replay_detected | :replay_capacity_exceeded}
  def check_and_put(identity, nonce, ttl_ms, max_entries \\ 100_000)
      when is_binary(identity) and is_binary(nonce) and is_integer(ttl_ms) and ttl_ms > 0 and
             is_integer(max_entries) and max_entries > 0 do
    ensure_table()
    now = System.monotonic_time(:millisecond)
    key = {:crypto.hash(:sha256, identity), :crypto.hash(:sha256, nonce)}
    expires_at = now + ttl_ms

    maybe_prune_expired(now)

    if live?(key, now) do
      {:error, :replay_detected}
    else
      delete_expired_key(key, now)
      reserve_and_insert(key, expires_at, max_entries)
    end
  end

  defp reserve_and_insert(key, expires_at, max_entries) do
    if :ets.update_counter(@table, @capacity_key, {2, 1}) > max_entries do
      :ets.update_counter(@table, @capacity_key, {2, -1})
      {:error, :replay_capacity_exceeded}
    else
      if :ets.insert_new(@table, {key, expires_at}) do
        :ok
      else
        :ets.update_counter(@table, @capacity_key, {2, -1})
        {:error, :replay_detected}
      end
    end
  end

  @doc "Delete all replay entries. Intended for tests and controlled resets."
  @spec clear() :: :ok
  def clear do
    ensure_table()
    :ets.delete_all_objects(@table)
    ensure_table()
  end

  defp live?(key, now) do
    case :ets.lookup(@table, key) do
      [{^key, expires_at}] when expires_at > now -> true
      _ -> false
    end
  end

  defp delete_expired_key(key, now) do
    removed =
      :ets.select_delete(@table, [
        {{key, :"$1"}, [{:"=<", :"$1", now}], [true]}
      ])

    :ets.update_counter(@table, @capacity_key, {2, -removed})
  end

  defp maybe_prune_expired(now) do
    case :ets.lookup(@table, @prune_key) do
      [{@prune_key, last_prune}] when now - last_prune < @prune_interval_ms ->
        :ok

      _ ->
        :ets.insert(@table, {@prune_key, now})
        prune_expired(now)
    end
  end

  defp prune_expired(now) do
    removed =
      :ets.select_delete(@table, [
        {{{:"$1", :"$2"}, :"$3"}, [{:<, :"$3", now}], [true]}
      ])

    :ets.update_counter(@table, @capacity_key, {2, -removed})
  end
end
