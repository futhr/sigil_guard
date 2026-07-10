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
  @default_max_line_bytes 1_048_576
  @read_chunk_bytes 65_536
  @hex_digest ~r/\A[0-9a-f]{64}\z/
  @atom_fields %{
    "anchor_digest" => :anchor_digest,
    "kind" => :kind,
    "uri" => :uri
  }

  @impl SigilGuard.Audit.Anchor.Store
  def put(record, opts) when is_map(record) and is_list(opts) do
    with :ok <- validate_options(opts),
         :ok <- validate_anchor(record),
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
    with :ok <- validate_options(opts),
         {:ok, digest} <- digest_from_ref(receipt_or_digest),
         {:ok, path} <- path_from_ref(receipt_or_digest, opts),
         {:ok, max_line_bytes} <- max_line_bytes(opts) do
      find_record(path, digest, max_line_bytes)
    end
  end

  def fetch(_, _), do: {:error, :missing_path}

  defp validate_options(opts) do
    if Keyword.keyword?(opts), do: :ok, else: {:error, :invalid_options}
  end

  defp validate_anchor(record) do
    case Anchor.validate(record) do
      :ok -> :ok
      {:error, :invalid_kind} -> {:error, :invalid_anchor}
      {:error, reason} -> {:error, reason}
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

  defp path_from_ref(%{} = ref, opts) do
    with :ok <- validate_receipt_uri(ref) do
      path_from_ref_with_opts(ref, opts)
    end
  end

  defp path_from_ref(ref, opts), do: path_from_ref_with_opts(ref, opts)

  defp path_from_ref_with_opts(ref, opts) do
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

  defp validate_receipt_uri(%{} = receipt) do
    case fetch_field(receipt, "uri") do
      {:ok, "file://" <> _ = uri} ->
        case path_from_uri(uri) do
          {:ok, _} -> :ok
          {:error, reason} -> {:error, reason}
        end

      {:ok, _} ->
        {:error, :missing_path}

      :error ->
        :ok
    end
  end

  defp path_from_uri("file://" <> _ = uri) do
    case URI.parse(uri) do
      %URI{scheme: "file", host: host, path: path}
      when host in [nil, ""] and is_binary(path) and path != "" ->
        {:ok, URI.decode(path)}

      %URI{scheme: "file", host: host} when is_binary(host) and host != "" ->
        {:error, :remote_file_uri}

      _ ->
        {:error, :missing_path}
    end
  end

  defp path_from_uri(_), do: {:error, :missing_path}

  defp metadata(opts) do
    case Keyword.get(opts, :metadata, %{}) do
      metadata when is_map(metadata) -> validate_metadata_json(metadata)
      _ -> {:error, :invalid_metadata}
    end
  end

  defp validate_metadata_json(metadata) do
    case Jason.encode(metadata) do
      {:ok, _} -> {:ok, metadata}
      {:error, _} -> {:error, :invalid_metadata}
    end
  rescue
    Protocol.UndefinedError -> {:error, :invalid_metadata}
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
  defp find_record(path, digest, max_line_bytes) do
    case File.open(path, [:read, :binary]) do
      {:ok, io} ->
        try do
          read_record_chunks(io, digest, max_line_bytes, "")
        after
          File.close(io)
        end

      {:error, :enoent} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp read_record_chunks(io, digest, max_line_bytes, buffer) do
    case IO.binread(io, @read_chunk_bytes) do
      :eof -> consume_final_line(buffer, digest, max_line_bytes)
      {:error, reason} -> {:error, reason}
      chunk -> consume_record_lines(io, digest, max_line_bytes, buffer <> chunk)
    end
  end

  defp consume_record_lines(io, digest, max_line_bytes, data) do
    case :binary.match(data, "\n") do
      {index, 1} when index > max_line_bytes ->
        {:error, :log_line_too_large}

      {index, 1} ->
        <<line::binary-size(^index), ?\n, rest::binary>> = data

        case consume_record_line(line, digest) do
          :not_found -> consume_record_lines(io, digest, max_line_bytes, rest)
          result -> result
        end

      :nomatch when byte_size(data) > max_line_bytes ->
        {:error, :log_line_too_large}

      :nomatch ->
        read_record_chunks(io, digest, max_line_bytes, data)
    end
  end

  defp consume_final_line("", _, _), do: {:error, :not_found}

  defp consume_final_line(line, digest, max_line_bytes) when byte_size(line) <= max_line_bytes,
    do: consume_record_line(line, digest) |> normalize_not_found()

  defp consume_final_line(_, _, _), do: {:error, :log_line_too_large}

  defp consume_record_line("", _), do: :not_found

  defp consume_record_line(line, digest) do
    case find_record_entry(line, :not_found, digest) do
      {:cont, :not_found} -> :not_found
      {:halt, result} -> result
    end
  end

  defp normalize_not_found(:not_found), do: {:error, :not_found}
  defp normalize_not_found(result), do: result

  defp max_line_bytes(opts) do
    case Keyword.get(opts, :max_line_bytes, @default_max_line_bytes) do
      value when is_integer(value) and value > 0 -> {:ok, value}
      _ -> {:error, :invalid_max_line_bytes}
    end
  end

  defp find_record_entry(line, :not_found, digest) do
    case decode_entry(line) do
      {:ok, %{"anchor_digest" => ^digest, "record" => record}} when is_map(record) ->
        matching_record_result(record, digest)

      {:ok, %{"anchor_digest" => ^digest}} ->
        {:halt, {:error, :invalid_log}}

      {:ok, %{"anchor_digest" => _}} ->
        {:cont, :not_found}

      {:ok, _} ->
        {:halt, {:error, :invalid_log}}

      {:error, reason} ->
        {:halt, {:error, reason}}
    end
  end

  defp matching_record_result(record, digest) do
    with :ok <- validate_anchor(record),
         true <- Anchor.digest(record) == digest do
      {:halt, {:ok, record}}
    else
      {:error, reason} -> {:halt, {:error, reason}}
      false -> {:halt, {:error, :digest_mismatch}}
    end
  end

  defp decode_entry(line) do
    case Jason.decode(line) do
      {:ok, decoded} when is_map(decoded) -> {:ok, decoded}
      {:ok, _} -> {:error, :invalid_log}
      {:error, _} -> {:error, :invalid_log}
    end
  end

  defp digest_from_ref(digest) when is_binary(digest) do
    if Regex.match?(@hex_digest, digest), do: {:ok, digest}, else: {:error, :missing_digest}
  end

  defp digest_from_ref(%{} = receipt) do
    case fetch_field(receipt, "anchor_digest") do
      {:ok, digest} when is_binary(digest) ->
        with {:ok, digest} <- digest_from_ref(digest),
             :ok <- validate_uri_digest(receipt, digest) do
          {:ok, digest}
        end

      {:ok, _} ->
        {:error, :missing_digest}

      :error ->
        case digest_from_uri(field(receipt, "uri")) do
          digest when is_binary(digest) -> digest_from_ref(digest)
          _ -> {:error, :missing_digest}
        end
    end
  end

  defp digest_from_ref(_), do: {:error, :missing_digest}

  defp validate_uri_digest(receipt, digest) do
    case digest_from_uri(field(receipt, "uri")) do
      uri_digest when is_binary(uri_digest) ->
        cond do
          not Regex.match?(@hex_digest, uri_digest) -> :ok
          uri_digest == digest -> :ok
          true -> {:error, :digest_mismatch}
        end

      _ ->
        :ok
    end
  end

  defp digest_from_uri("file://" <> _ = uri) do
    uri
    |> URI.parse()
    |> Map.get(:fragment)
  end

  defp digest_from_uri(_), do: nil

  defp field(map, key) when is_map(map) do
    case fetch_field(map, key) do
      {:ok, value} -> value
      :error -> nil
    end
  end

  defp fetch_field(map, key) when is_map(map) do
    case Map.fetch(map, key) do
      {:ok, value} -> {:ok, value}
      :error -> Map.fetch(map, Map.fetch!(@atom_fields, key))
    end
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
