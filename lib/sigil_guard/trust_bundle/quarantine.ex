defmodule SigilGuard.TrustBundle.Quarantine do
  @moduledoc """
  In-memory quarantine records for failed trust-bundle loads and verifies.

  Records are per-boot diagnostic metadata. They deliberately store reasons,
  bundle ids, digests, sequences, timestamps, and evidence references only;
  they do not retain payload bytes or signature material.
  """

  @table :sigil_guard_trust_bundle_quarantine

  @typedoc "Audit-safe trust-bundle quarantine record."
  @type t :: %{
          reason: SigilGuard.TrustBundle.load_error(),
          bundle_id: String.t() | nil,
          bundle_digest: String.t() | nil,
          sequence: pos_integer() | nil,
          quarantined_at: String.t(),
          evidence: [%{kind: String.t(), ref: String.t()}]
        }

  @doc """
  Create the quarantine ETS table if it does not already exist.
  """
  @spec ensure_table() :: :ok
  def ensure_table do
    case :ets.whereis(@table) do
      :undefined ->
        try do
          :ets.new(@table, [
            :named_table,
            :public,
            :ordered_set,
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
  Record a trust-bundle load or verify failure.
  """
  @spec record(reason :: atom(), info :: map()) :: t()
  def record(reason, info) when is_atom(reason) and is_map(info) do
    ensure_table()

    record = %{
      reason: reason,
      bundle_id: bundle_id(info),
      bundle_digest: bundle_digest(info),
      sequence: sequence(info),
      quarantined_at: quarantined_at(info),
      evidence: evidence(info)
    }

    :ets.insert(@table, {System.unique_integer([:monotonic, :positive]), record})
    emit_telemetry(record, info)
    record
  end

  @doc """
  List all quarantine records, oldest first.
  """
  @spec list() :: [t()]
  def list do
    ensure_table()

    @table
    |> :ets.tab2list()
    |> Enum.sort_by(fn {id, _} -> id end)
    |> Enum.map(fn {_, record} -> record end)
  end

  @doc """
  List quarantine records for one bundle id.
  """
  @spec list(bundle_id :: String.t()) :: [t()]
  def list(bundle_id) when is_binary(bundle_id) do
    Enum.filter(list(), &(Map.get(&1, :bundle_id) == bundle_id))
  end

  @doc false
  @spec clear() :: :ok
  def clear do
    ensure_table()
    :ets.delete_all_objects(@table)
    :ok
  end

  defp bundle_id(%{bundle_id: bundle_id}) when is_binary(bundle_id), do: bundle_id

  defp bundle_id(%{document: %{"bundle_id" => bundle_id}}) when is_binary(bundle_id),
    do: bundle_id

  defp bundle_id(%{envelope: envelope}) do
    envelope
    |> decoded_document()
    |> document_bundle_id()
  end

  defp bundle_id(_), do: nil

  defp document_bundle_id(%{"bundle_id" => bundle_id}) when is_binary(bundle_id), do: bundle_id
  defp document_bundle_id(_), do: nil

  defp bundle_digest(%{bundle_digest: digest}) when is_binary(digest), do: digest
  defp bundle_digest(%{payload: payload}) when is_binary(payload), do: digest(payload)

  defp bundle_digest(%{envelope: envelope}) do
    envelope
    |> decoded_payload()
    |> payload_digest()
  end

  defp bundle_digest(_), do: nil

  defp payload_digest({:ok, payload}) when is_binary(payload), do: digest(payload)
  defp payload_digest(_), do: nil

  defp digest(payload), do: Base.encode16(:crypto.hash(:sha256, payload), case: :lower)

  defp sequence(%{sequence: sequence}) when is_integer(sequence) and sequence > 0, do: sequence
  defp sequence(%{document: %{"sequence" => sequence}}), do: positive_integer(sequence)

  defp sequence(%{envelope: envelope}) do
    envelope
    |> decoded_document()
    |> document_sequence()
  end

  defp sequence(_), do: nil

  defp document_sequence(%{"sequence" => sequence}), do: positive_integer(sequence)
  defp document_sequence(_), do: nil

  defp positive_integer(value) when is_binary(value) do
    case Integer.parse(value) do
      {integer, ""} when integer > 0 -> integer
      _ -> nil
    end
  end

  defp positive_integer(_), do: nil

  defp quarantined_at(%{now: %DateTime{} = now}), do: DateTime.to_iso8601(now)
  defp quarantined_at(_), do: DateTime.utc_now(:millisecond) |> DateTime.to_iso8601()

  defp evidence(%{evidence: evidence}) when is_list(evidence) do
    Enum.reduce(evidence, [], fn ref, refs ->
      case evidence_ref(ref) do
        {:ok, normalized} -> [normalized | refs]
        :error -> refs
      end
    end)
    |> Enum.reverse()
  end

  defp evidence(_), do: []

  defp evidence_ref(%{kind: kind, ref: ref}) when is_binary(kind) and is_binary(ref) do
    {:ok, %{kind: kind, ref: ref}}
  end

  defp evidence_ref(%{"kind" => kind, "ref" => ref}) when is_binary(kind) and is_binary(ref) do
    {:ok, %{kind: kind, ref: ref}}
  end

  defp evidence_ref(_), do: :error

  defp emit_telemetry(record, info) do
    :telemetry.execute(
      [:sigil_guard, :trust_bundle, :quarantine],
      %{count: 1},
      %{
        reason: record.reason,
        bundle_id: record.bundle_id,
        bundle_digest: record.bundle_digest,
        dev: Map.get(info, :dev, false)
      }
    )
  end

  defp decoded_document(envelope) do
    with {:ok, payload} when is_binary(payload) <- decoded_payload(envelope),
         {:ok, %{} = document} <- Jason.decode(payload) do
      document
    else
      _ -> nil
    end
  end

  defp decoded_payload(%{} = envelope) do
    envelope
    |> field("payload")
    |> decode_base64()
  end

  defp decoded_payload(_), do: nil

  defp field(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} -> value
      :error -> Map.get(map, atom_key(key))
    end
  end

  defp atom_key("payload"), do: :payload

  defp decode_base64(value) when is_binary(value) do
    with :error <- Base.url_decode64(value, padding: false),
         :error <- Base.url_decode64(value, padding: true),
         :error <- Base.decode64(value, padding: false),
         :error <- Base.decode64(value, padding: true) do
      nil
    end
  end

  defp decode_base64(_), do: nil
end
