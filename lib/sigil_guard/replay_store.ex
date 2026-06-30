defmodule SigilGuard.ReplayStore do
  @moduledoc """
  ETS-backed replay protection for signed SIGIL envelopes.

  The store records `{identity, nonce}` pairs for a bounded TTL. It is kept
  separate from signature verification so callers can choose stateless
  verification for compatibility tests and enable replay protection at MCP or
  API trust boundaries.
  """

  @table :sigil_guard_replay

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

          :ok
        rescue
          ArgumentError -> :ok
        end

      _ ->
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

    prune_expired(now)

    case :ets.lookup(@table, key) do
      [{^key, expires_at}] when expires_at > now ->
        {:error, :replay_detected}

      _ ->
        :ets.insert(@table, {key, now + ttl_ms})
        :ok
    end
  end

  @doc "Delete all replay entries. Intended for tests and controlled resets."
  @spec clear() :: :ok
  def clear do
    ensure_table()
    :ets.delete_all_objects(@table)
    :ok
  end

  defp prune_expired(now) do
    :ets.select_delete(@table, [
      {{{:"$1", :"$2"}, :"$3"}, [{:<, :"$3", now}], [true]}
    ])
  end
end
