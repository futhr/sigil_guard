defmodule SigilGuard.Audit.Anchor.Store.LocalFile do
  @moduledoc """
  Append-only local JSONL store for audit anchor records.

  This store is useful for development, tests, and deployments that ship the
  JSONL file to append-only or WORM storage using external infrastructure. Each
  line contains a receipt plus the compact anchor record. Fetching validates the
  record digest before returning it, so corrupted or mismatched log entries are
  rejected.
  """

  @behaviour SigilGuard.Audit.Anchor.Store

  alias SigilGuard.Audit.Anchor

  @kind "sigil_guard.audit.anchor.receipt"
  @version 1
  @anchor_kind "sigil_guard.audit.anchor"
  @atom_fields %{
    "anchor_digest" => :anchor_digest,
    "kind" => :kind,
    "uri" => :uri
  }

  @impl SigilGuard.Audit.Anchor.Store
  def put(record, opts) when is_map(record) and is_list(opts) do
    with :ok <- validate_anchor(record),
         :ok <- allow_local_receipt(opts),
         {:ok, path} <- path_from_opts(opts),
         {:ok, metadata} <- metadata(opts),
         :ok <- ensure_parent(path),
         {:ok, receipt} <- receipt(record, path, metadata),
         :ok <- append_entry(path, receipt, record) do
      {:ok, receipt}
    end
  end

  def put(_, _), do: {:error, :invalid_anchor}

  @impl SigilGuard.Audit.Anchor.Store
  def fetch(receipt_or_digest, opts) when is_list(opts) do
    with {:ok, digest} <- digest_from_ref(receipt_or_digest),
         {:ok, path} <- path_from_ref(receipt_or_digest, opts) do
      find_record(path, digest)
    end
  end

  def fetch(_, _), do: {:error, :missing_path}

  defp validate_anchor(record) do
    if field(record, "kind") == @anchor_kind do
      :ok
    else
      {:error, :invalid_anchor}
    end
  end

  defp allow_local_receipt(opts) do
    if Keyword.get(opts, :require_worm, false) == true do
      {:error, :worm_required}
    else
      :ok
    end
  end

  defp path_from_opts(opts) do
    case Keyword.get(opts, :path) do
      path when is_binary(path) and path != "" -> {:ok, Path.expand(path)}
      _ -> {:error, :missing_path}
    end
  end

  defp path_from_ref(ref, opts) do
    case path_from_opts(opts) do
      {:ok, path} ->
        {:ok, path}

      {:error, :missing_path} ->
        receipt_path(ref)
    end
  end

  defp receipt_path(%{} = receipt) do
    receipt
    |> field("uri")
    |> path_from_uri()
  end

  defp receipt_path(_), do: {:error, :missing_path}

  defp path_from_uri("file://" <> _ = uri) do
    case URI.parse(uri) do
      %URI{scheme: "file", path: path} when is_binary(path) and path != "" ->
        {:ok, URI.decode(path)}

      _ ->
        {:error, :missing_path}
    end
  end

  defp path_from_uri(_), do: {:error, :missing_path}

  defp metadata(opts) do
    case Keyword.get(opts, :metadata, %{}) do
      metadata when is_map(metadata) -> {:ok, metadata}
      _ -> {:error, :invalid_metadata}
    end
  end

  defp receipt(record, path, metadata) do
    digest = Anchor.digest(record)

    {:ok,
     %{
       "kind" => @kind,
       "version" => @version,
       "storage" => "local_file",
       "uri" => file_uri(path, digest),
       "anchor_digest" => digest,
       "stored_at" => timestamp(),
       "worm" => false,
       "metadata" => metadata
     }}
  end

  # sobelow_skip ["Traversal.FileModule"]
  defp ensure_parent(path), do: File.mkdir_p(Path.dirname(path))

  # sobelow_skip ["Traversal.FileModule"]
  defp append_entry(path, receipt, record) do
    entry =
      receipt
      |> Map.put("record", record)
      |> Jason.encode!()

    case File.write(path, [entry, ?\n], [:append, :binary]) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  # sobelow_skip ["Traversal.FileModule"]
  defp find_record(path, digest) do
    case File.read(path) do
      {:ok, body} ->
        body
        |> String.split("\n", trim: true)
        |> find_record_line(digest)

      {:error, :enoent} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp find_record_line(lines, digest) do
    result = Enum.reduce_while(lines, :not_found, &find_record_entry(&1, &2, digest))

    case result do
      :not_found -> {:error, :not_found}
      result -> result
    end
  end

  defp find_record_entry(line, :not_found, digest) do
    case decode_entry(line) do
      {:ok, %{"anchor_digest" => ^digest, "record" => record}} when is_map(record) ->
        matching_record_result(record, digest)

      {:ok, %{"anchor_digest" => _}} ->
        {:cont, :not_found}

      {:ok, _} ->
        {:halt, {:error, :invalid_log}}

      {:error, reason} ->
        {:halt, {:error, reason}}
    end
  end

  defp matching_record_result(record, digest) do
    if Anchor.digest(record) == digest do
      {:halt, {:ok, record}}
    else
      {:halt, {:error, :digest_mismatch}}
    end
  end

  defp decode_entry(line) do
    case Jason.decode(line) do
      {:ok, decoded} when is_map(decoded) -> {:ok, decoded}
      {:ok, _} -> {:error, :invalid_log}
      {:error, _} -> {:error, :invalid_log}
    end
  end

  defp digest_from_ref(digest) when is_binary(digest) and byte_size(digest) == 64 do
    {:ok, digest}
  end

  defp digest_from_ref(%{} = receipt) do
    case field(receipt, "anchor_digest") || digest_from_uri(field(receipt, "uri")) do
      digest when is_binary(digest) and byte_size(digest) == 64 -> {:ok, digest}
      _ -> {:error, :missing_digest}
    end
  end

  defp digest_from_ref(_), do: {:error, :missing_digest}

  defp digest_from_uri("file://" <> _ = uri) do
    uri
    |> URI.parse()
    |> Map.get(:fragment)
  end

  defp digest_from_uri(_), do: nil

  defp field(map, key) when is_map(map) do
    Map.get(map, key) || Map.get(map, Map.fetch!(@atom_fields, key))
  end

  defp file_uri(path, digest) do
    encoded_path =
      path
      |> String.split("/", trim: false)
      |> Enum.map_join("/", &URI.encode/1)

    "file://#{encoded_path}##{digest}"
  end

  defp timestamp do
    DateTime.utc_now(:millisecond)
    |> DateTime.to_iso8601()
  end
end
