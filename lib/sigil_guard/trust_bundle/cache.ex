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

  @type root_pin :: %{
          version: pos_integer(),
          threshold: pos_integer(),
          keyids: [String.t()],
          keys: %{String.t() => binary()}
        }
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
      [{^bundle_id, bundle, _, _, _, _}] -> {:ok, bundle}
      [] -> :error
    end
  end

  @doc false
  @spec root_pin(bundle_id :: String.t()) :: {:ok, root_pin()} | :error
  def root_pin(bundle_id) when is_binary(bundle_id) do
    ensure_table()

    case :ets.lookup(@table, bundle_id) do
      [{^bundle_id, _, _, nil, _, _}] -> :error
      [{^bundle_id, _, _, pin, _, _}] -> {:ok, pin}
      [] -> :error
    end
  end

  @doc false
  @spec revoked_keyids(bundle_id :: String.t()) :: MapSet.t(String.t())
  def revoked_keyids(bundle_id) when is_binary(bundle_id) do
    ensure_table()

    case :ets.lookup(@table, bundle_id) do
      [{^bundle_id, _, _, _, _, revoked}] -> revoked
      [] -> MapSet.new()
    end
  end

  @doc false
  @spec rotation_digest(bundle_id :: String.t(), root_version :: pos_integer()) ::
          {:ok, String.t()} | :error
  def rotation_digest(bundle_id, root_version)
      when is_binary(bundle_id) and is_integer(root_version) do
    ensure_table()

    case :ets.lookup(@table, bundle_id) do
      [{^bundle_id, _, _, _, digests, _}] -> Map.fetch(digests, root_version)
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
      [{^bundle_id, cached, floor, _, _, revoked}] -> put_existing(bundle, cached, floor, revoked)
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
      [{^bundle_id, _, floor, _, _, _}] -> floor
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

    :ets.insert(
      @table,
      {bundle.bundle_id, bundle, floor, build_root_pin(bundle), rotation_digests(bundle),
       collect_revoked_keyids(bundle)}
    )

    {:ok, bundle}
  end

  defp put_existing(bundle, cached, floor, revoked) do
    cond do
      same_snapshot?(bundle, cached) ->
        {:ok, cached}

      bundle.sequence <= cached.sequence ->
        {:error, :sequence_below_floor}

      bundle.sequence < floor ->
        {:error, :sequence_below_floor}

      root_version_below_cached?(bundle, cached) ->
        {:error, :sequence_below_floor}

      true ->
        accepted = accepted_floor(floor, bundle)

        :ets.insert(
          @table,
          {bundle.bundle_id, bundle, accepted, build_root_pin(cached), rotation_digests(bundle),
           MapSet.union(revoked, collect_revoked_keyids(bundle))}
        )

        {:ok, bundle}
    end
  end

  defp same_snapshot?(bundle, cached) do
    bundle.sequence == cached.sequence and bundle.digest == cached.digest
  end

  defp root_version_below_cached?(bundle, cached) do
    bundle.root_version < cached.root_version
  end

  defp accepted_floor(floor, bundle) do
    max(floor, max(rollback_floor(bundle), bundle.sequence))
  end

  defp rollback_floor(%TrustBundle{document: %{"rollback_floor" => rollback_floor}})
       when is_binary(rollback_floor) do
    String.to_integer(rollback_floor)
  end

  defp rollback_floor(_), do: 0

  defp build_root_pin(
         %TrustBundle{document: %{"roles" => %{"root" => root}, "keys" => _}} = bundle
       ) do
    %{
      version: bundle.root_version,
      threshold: Map.fetch!(root, "threshold"),
      keyids: Map.fetch!(root, "keyids"),
      keys: decoded_keys(bundle.document)
    }
  end

  defp build_root_pin(_), do: nil

  defp rotation_digests(bundle) do
    bundle.document
    |> Map.get("rotation_chain", [])
    |> Map.new(fn envelope ->
      document = envelope_document!(envelope)
      {String.to_integer(Map.fetch!(document, "root_version")), document_digest!(document)}
    end)
  end

  defp envelope_document!(envelope) do
    envelope
    |> Map.fetch!("payload")
    |> Base.url_decode64!(padding: false)
    |> Jason.decode!()
  end

  defp document_digest!(document) do
    {:ok, bytes} = SigilGuard.Canonical.JCS.encode(document)
    Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
  end

  defp decoded_keys(%{"keys" => keys}) do
    Map.new(keys, fn {keyid, %{"public_key" => encoded}} ->
      {:ok, public_key} = Base.url_decode64(encoded, padding: false)
      {keyid, public_key}
    end)
  end

  defp collect_revoked_keyids(%TrustBundle{document: document}) do
    document
    |> Map.get("revocations", [])
    |> Enum.filter(&(Map.get(&1, "kind") == "key"))
    |> Enum.map(&Map.fetch!(&1, "id"))
    |> MapSet.new()
  end
end
