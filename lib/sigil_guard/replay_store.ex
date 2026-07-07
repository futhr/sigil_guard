defmodule SigilGuard.ReplayStore do
  @moduledoc """
  ETS-backed replay protection for signed SIGIL envelopes and confirmation tokens.

  The store records `{identity, nonce}` pairs for a bounded TTL. It is kept
  separate from signature verification so callers can choose stateless
  verification for compatibility tests and enable replay protection at MCP,
  approval, or API trust boundaries.
  """

  @table :sigil_guard_replay
  @prune_key {:sigil_guard_replay_store, :meta, :last_prune}
  @prune_interval_ms 60_000

  @doc "Create the replay table if it does not already exist."
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

          :ets.insert_new(@table, {@prune_key, 0})
          :ok
        rescue
          ArgumentError ->
            :ets.insert_new(@table, {@prune_key, 0})
            :ok
        end

      _ ->
        :ets.insert_new(@table, {@prune_key, 0})
        :ok
    end
  end

  @doc """
  Record a nonce if it has not been seen within its TTL.

  Returns `{:error, :replay_detected}` when the same identity/nonce pair is
  still live.
  """
  @spec check_and_put(String.t(), String.t(), pos_integer()) ::
          :ok | {:error, :replay_detected}
  def check_and_put(identity, nonce, ttl_ms)
      when is_binary(identity) and is_binary(nonce) and is_integer(ttl_ms) and ttl_ms > 0 do
    ensure_table()
    now = System.system_time(:millisecond)
    key = {identity, nonce}
    expires_at = now + ttl_ms

    maybe_prune_expired(now)

    cond do
      :ets.insert_new(@table, {key, expires_at}) ->
        :ok

      live?(key, now) ->
        {:error, :replay_detected}

      true ->
        delete_expired_key(key, now)

        if :ets.insert_new(@table, {key, expires_at}) do
          :ok
        else
          {:error, :replay_detected}
        end
    end
  end

  @doc "Delete all replay entries. Intended for tests and controlled resets."
  @spec clear() :: :ok
  def clear do
    ensure_table()
    :ets.delete_all_objects(@table)
    :ets.insert_new(@table, {@prune_key, 0})
    :ok
  end

  defp live?(key, now) do
    case :ets.lookup(@table, key) do
      [{^key, expires_at}] when expires_at > now -> true
      _ -> false
    end
  end

  defp delete_expired_key(key, now) do
    :ets.select_delete(@table, [
      {{key, :"$1"}, [{:"=<", :"$1", now}], [true]}
    ])
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
    :ets.select_delete(@table, [
      {{{:"$1", :"$2"}, :"$3"}, [{:<, :"$3", now}], [true]}
    ])
  end
end
