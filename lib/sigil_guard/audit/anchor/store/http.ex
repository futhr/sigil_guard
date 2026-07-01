defmodule SigilGuard.Audit.Anchor.Store.HTTP do
  @moduledoc """
  HTTP store adapter for external audit anchor records.

  This adapter is intentionally service-neutral. It posts compact anchor records
  to an append-only or WORM-backed service and fetches them later by receipt or
  digest. The remote service can be an internal audit endpoint, object-lock
  gateway, or transparency-log facade.

  ## Endpoint Contract

  `put/2` sends `POST /audit/anchors` by default with a JSON object containing:

    * `"kind"` - `"sigil_guard.audit.anchor.put"`
    * `"version"` - `1`
    * `"anchor_digest"` - SHA-256 digest of the canonical anchor record
    * `"record"` - compact anchor record
    * `"metadata"` - caller-supplied metadata

  A successful `200`, `201`, or `202` response may return either a receipt
  object or `%{"receipt" => receipt}`. Missing receipt fields are filled from
  the request and response location, while explicitly malformed receipt fields
  are rejected. Pass `require_worm: true` to reject receipts unless the remote
  service explicitly returns `"worm": true`. Pass
  `require_receipt_signature: true` with `receipt_public_keys` or
  `receipt_public_key_b64u` to require Ed25519 provenance over canonical
  receipt bytes.

  `fetch/2` sends `GET /audit/anchors/:digest` by default and accepts either a
  raw anchor record or `%{"record" => record}` / `%{"anchor" => record}`.
  Fetched records are rejected when their canonical digest does not match the
  requested digest. When no explicit fetch URL is configured and the adapter
  falls back to a receipt URI, private, loopback, link-local, and localhost
  targets are rejected unless `allow_private_receipt_url: true` is passed.
  """

  @behaviour SigilGuard.Audit.Anchor.Store

  alias SigilGuard.Audit.Anchor
  alias SigilGuard.Audit.Anchor.Receipt

  @kind "sigil_guard.audit.anchor.receipt"
  @version 1
  @put_kind "sigil_guard.audit.anchor.put"
  @default_put_path "/audit/anchors"
  @default_fetch_path "/audit/anchors/:digest"
  @default_timeout_ms 5_000
  @success_statuses [200, 201, 202]
  @atom_fields %{
    "anchor" => :anchor,
    "anchor_digest" => :anchor_digest,
    "kind" => :kind,
    "metadata" => :metadata,
    "record" => :record,
    "storage" => :storage,
    "stored_at" => :stored_at,
    "uri" => :uri,
    "version" => :version,
    "worm" => :worm
  }
  @hex_digest ~r/\A[0-9a-f]{64}\z/

  @impl SigilGuard.Audit.Anchor.Store
  def put(record, opts) when is_map(record) and is_list(opts) do
    with :ok <- validate_anchor(record),
         {:ok, url} <- put_url(opts),
         {:ok, metadata} <- metadata(opts),
         {:ok, headers} <- headers(opts),
         {:ok, timeout} <- timeout(opts),
         {:ok, body, response_headers} <- post_anchor(url, record, metadata, headers, timeout),
         {:ok, receipt} <- normalize_receipt(body, record, url, metadata, response_headers),
         :ok <- validate_required_worm(receipt, opts),
         :ok <- verify_required_receipt_signature(receipt, opts) do
      {:ok, receipt}
    end
  end

  def put(_, _), do: {:error, :invalid_anchor}

  @impl SigilGuard.Audit.Anchor.Store
  def fetch(receipt_or_digest, opts) when is_list(opts) do
    with :ok <- verify_fetch_receipt_reference(receipt_or_digest, opts),
         {:ok, digest} <- digest_from_ref(receipt_or_digest),
         {:ok, url} <- fetch_url(receipt_or_digest, opts, digest),
         {:ok, headers} <- headers(opts),
         {:ok, timeout} <- timeout(opts),
         {:ok, body} <- get_anchor(url, headers, timeout),
         {:ok, record} <- normalize_record(body),
         :ok <- verify_digest(record, digest) do
      {:ok, record}
    end
  end

  def fetch(_, _), do: {:error, :missing_url}

  defp validate_anchor(record) do
    case Anchor.validate(record) do
      :ok -> :ok
      {:error, :invalid_kind} -> {:error, :invalid_anchor}
      {:error, reason} -> {:error, reason}
    end
  end

  defp put_url(opts) do
    cond do
      nonempty_binary?(Keyword.get(opts, :put_url)) ->
        {:ok, Keyword.fetch!(opts, :put_url)}

      nonempty_binary?(Keyword.get(opts, :url)) ->
        {:ok,
         join_url(Keyword.fetch!(opts, :url), Keyword.get(opts, :put_path, @default_put_path))}

      nonempty_binary?(Keyword.get(opts, :base_url)) ->
        {:ok,
         join_url(
           Keyword.fetch!(opts, :base_url),
           Keyword.get(opts, :put_path, @default_put_path)
         )}

      true ->
        {:error, :missing_url}
    end
  end

  defp fetch_url(ref, opts, digest) do
    cond do
      nonempty_binary?(Keyword.get(opts, :fetch_url)) ->
        {:ok, replace_digest(Keyword.fetch!(opts, :fetch_url), digest)}

      nonempty_binary?(Keyword.get(opts, :url)) ->
        {:ok,
         Keyword.fetch!(opts, :url)
         |> join_url(Keyword.get(opts, :fetch_path, @default_fetch_path))
         |> replace_digest(digest)}

      nonempty_binary?(Keyword.get(opts, :base_url)) ->
        {:ok,
         Keyword.fetch!(opts, :base_url)
         |> join_url(Keyword.get(opts, :fetch_path, @default_fetch_path))
         |> replace_digest(digest)}

      true ->
        ref
        |> receipt_uri()
        |> fetch_url_from_receipt(opts)
    end
  end

  defp fetch_url_from_receipt(uri, opts) when is_binary(uri) do
    case URI.parse(uri) do
      %URI{scheme: scheme, host: host} = parsed
      when scheme in ["http", "https"] and is_binary(host) and host != "" ->
        with :ok <- validate_receipt_url_host(host, opts) do
          {:ok, URI.to_string(%{parsed | fragment: nil})}
        end

      _ ->
        {:error, :missing_url}
    end
  end

  defp fetch_url_from_receipt(_, _), do: {:error, :missing_url}

  defp validate_receipt_url_host(host, opts) do
    cond do
      Keyword.get(opts, :allow_private_receipt_url, false) == true ->
        :ok

      private_receipt_host?(host) ->
        {:error, :unsafe_receipt_url}

      true ->
        :ok
    end
  end

  defp private_receipt_host?(host) do
    host = String.downcase(host)

    local_hostname?(host) or private_ip?(host)
  end

  defp local_hostname?("localhost"), do: true
  defp local_hostname?(host), do: String.ends_with?(host, ".localhost")

  defp private_ip?(host) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, address} -> private_ip_tuple?(address)
      {:error, _} -> false
    end
  rescue
    ArgumentError -> false
  end

  defp private_ip_tuple?({0, _, _, _}), do: true
  defp private_ip_tuple?({10, _, _, _}), do: true
  defp private_ip_tuple?({100, second, _, _}) when second in 64..127, do: true
  defp private_ip_tuple?({127, _, _, _}), do: true
  defp private_ip_tuple?({169, 254, _, _}), do: true
  defp private_ip_tuple?({172, second, _, _}) when second in 16..31, do: true
  defp private_ip_tuple?({192, 168, _, _}), do: true
  defp private_ip_tuple?({198, second, _, _}) when second in 18..19, do: true
  defp private_ip_tuple?({0, 0, 0, 0, 0, 0, 0, 0}), do: true
  defp private_ip_tuple?({0, 0, 0, 0, 0, 0, 0, 1}), do: true

  defp private_ip_tuple?({first, _, _, _, _, _, _, _}) do
    Bitwise.band(first, 0xFE00) == 0xFC00 or Bitwise.band(first, 0xFFC0) == 0xFE80
  end

  defp private_ip_tuple?(_), do: false

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

  defp headers(opts) do
    extra_headers = Keyword.get(opts, :headers, [])

    with {:ok, extra_headers} <- normalize_headers(extra_headers) do
      {:ok,
       [{"accept", "application/json"}, {"content-type", "application/json"} | extra_headers]}
    end
  end

  defp normalize_headers(headers) when is_map(headers) do
    headers
    |> Map.to_list()
    |> normalize_headers()
  end

  defp normalize_headers(headers) when is_list(headers) do
    if Enum.all?(headers, &valid_header?/1) do
      normalized =
        Enum.map(headers, fn {key, value} ->
          {to_string(key), to_string(value)}
        end)

      {:ok, normalized}
    else
      {:error, :invalid_headers}
    end
  end

  defp normalize_headers(_), do: {:error, :invalid_headers}

  defp valid_header?({key, value})
       when (is_binary(key) or is_atom(key)) and (is_binary(value) or is_atom(value)),
       do: true

  defp valid_header?(_), do: false

  defp post_anchor(url, record, metadata, headers, timeout) do
    body =
      %{
        "kind" => @put_kind,
        "version" => @version,
        "anchor_digest" => Anchor.digest(record),
        "record" => record,
        "metadata" => metadata
      }
      |> Jason.encode_to_iodata!()

    Finch.build(:post, url, headers, body)
    |> request_json(timeout, allow_empty?: true)
    |> response_with_headers()
  end

  defp get_anchor(url, headers, timeout) do
    Finch.build(:get, url, headers)
    |> request_json(timeout, allow_empty?: false)
    |> response_body()
  end

  defp request_json(request, timeout, opts) do
    case request(request, timeout) do
      {:ok, %Finch.Response{status: status, body: body, headers: headers}}
      when status in @success_statuses ->
        with {:ok, decoded} <- decode_object(body, opts) do
          {:ok, decoded, headers}
        end

      {:ok, %Finch.Response{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, normalize_request_error(reason)}
    end
  end

  defp request(request, timeout) do
    Finch.request(request, SigilGuard.Finch, receive_timeout: timeout)
  rescue
    error in ArgumentError -> {:error, error}
  catch
    :exit, {:noproc, _} -> {:error, :finch_not_started}
    :exit, reason -> {:error, {:finch_exit, reason}}
  end

  defp normalize_request_error(%ArgumentError{message: "unknown registry: " <> _}),
    do: :finch_not_started

  defp normalize_request_error(reason), do: reason

  defp response_with_headers({:ok, body, headers}), do: {:ok, body, headers}
  defp response_with_headers({:error, reason}), do: {:error, reason}

  defp response_body({:ok, body, _}), do: {:ok, body}
  defp response_body({:error, reason}), do: {:error, reason}

  defp decode_object("", opts) do
    if Keyword.get(opts, :allow_empty?, false), do: {:ok, %{}}, else: {:error, :invalid_body}
  end

  defp decode_object(body, _) do
    case Jason.decode(body) do
      {:ok, decoded} when is_map(decoded) -> {:ok, decoded}
      {:ok, _} -> {:error, :invalid_body}
      {:error, _} -> {:error, :invalid_body}
    end
  end

  defp normalize_receipt(body, record, request_url, metadata, response_headers) do
    digest = Anchor.digest(record)

    with {:ok, receipt} <- receipt_body(body),
         :ok <- verify_receipt_digest(receipt, digest),
         :ok <- validate_uri_digest(receipt, digest),
         :ok <- validate_receipt_fields(receipt) do
      {:ok, build_receipt(receipt, digest, request_url, metadata, response_headers)}
    end
  end

  defp verify_receipt_digest(receipt, digest) do
    case fetch_field(receipt, "anchor_digest") do
      {:ok, ^digest} ->
        :ok

      {:ok, received_digest} when is_binary(received_digest) ->
        {:error, :digest_mismatch}

      {:ok, _} ->
        {:error, :invalid_receipt}

      :error ->
        :ok
    end
  end

  defp validate_receipt_fields(receipt) do
    with :ok <- validate_receipt_kind(receipt),
         :ok <- validate_receipt_version(receipt),
         :ok <- validate_optional_binary(receipt, "storage"),
         :ok <- validate_optional_binary(receipt, "uri"),
         :ok <- validate_optional_binary(receipt, "stored_at"),
         :ok <- validate_optional_boolean(receipt, "worm") do
      validate_optional_metadata(receipt)
    end
  end

  defp validate_receipt_kind(receipt) do
    case fetch_field(receipt, "kind") do
      {:ok, @kind} -> :ok
      {:ok, _} -> {:error, :invalid_receipt}
      :error -> :ok
    end
  end

  defp validate_receipt_version(receipt) do
    case fetch_field(receipt, "version") do
      {:ok, @version} -> :ok
      {:ok, _} -> {:error, :invalid_receipt}
      :error -> :ok
    end
  end

  defp validate_optional_binary(receipt, key) do
    case fetch_field(receipt, key) do
      {:ok, value} when is_binary(value) and value != "" -> :ok
      {:ok, _} -> {:error, :invalid_receipt}
      :error -> :ok
    end
  end

  defp validate_optional_boolean(receipt, key) do
    case fetch_field(receipt, key) do
      {:ok, value} when is_boolean(value) -> :ok
      {:ok, _} -> {:error, :invalid_receipt}
      :error -> :ok
    end
  end

  defp validate_optional_metadata(receipt) do
    case fetch_field(receipt, "metadata") do
      {:ok, metadata} when is_map(metadata) -> :ok
      {:ok, _} -> {:error, :invalid_receipt}
      :error -> :ok
    end
  end

  defp build_receipt(receipt, digest, request_url, metadata, response_headers) do
    receipt
    |> signed_receipt_field()
    |> Map.merge(%{
      "kind" => field(receipt, "kind") || @kind,
      "version" => field(receipt, "version") || @version,
      "storage" => field(receipt, "storage") || "http",
      "uri" =>
        receipt_uri(receipt) || location_header(response_headers) || "#{request_url}##{digest}",
      "anchor_digest" => digest,
      "stored_at" => field(receipt, "stored_at") || timestamp(),
      "worm" => field(receipt, "worm") == true,
      "metadata" => field(receipt, "metadata") || metadata
    })
  end

  defp validate_required_worm(receipt, opts) do
    if Keyword.get(opts, :require_worm, false) == true and field(receipt, "worm") != true do
      {:error, :worm_required}
    else
      :ok
    end
  end

  defp verify_fetch_receipt_reference(ref, opts) do
    cond do
      Keyword.get(opts, :require_receipt_signature, false) != true ->
        :ok

      is_map(ref) ->
        verify_required_receipt_signature(ref, opts)

      true ->
        {:error, :missing_receipt}
    end
  end

  defp verify_required_receipt_signature(receipt, opts) do
    if Keyword.get(opts, :require_receipt_signature, false) do
      Receipt.verify(receipt, receipt_verify_opts(opts))
    else
      :ok
    end
  end

  defp receipt_verify_opts(opts) do
    [
      public_keys: Keyword.get(opts, :receipt_public_keys, %{}),
      public_key_b64u: Keyword.get(opts, :receipt_public_key_b64u)
    ]
  end

  defp signed_receipt_field(receipt) do
    case Receipt.signature(receipt) do
      nil -> %{}
      signature -> %{"signature" => signature}
    end
  end

  defp receipt_body(%{"receipt" => receipt}) when is_map(receipt), do: {:ok, receipt}
  defp receipt_body(%{"receipt" => _}), do: {:error, :invalid_receipt}
  defp receipt_body(body) when is_map(body), do: {:ok, body}

  defp normalize_record(%{"record" => record}) when is_map(record), do: normalize_record(record)
  defp normalize_record(%{"anchor" => record}) when is_map(record), do: normalize_record(record)

  defp normalize_record(record) when is_map(record) do
    case validate_anchor(record) do
      :ok -> {:ok, record}
      {:error, reason} -> {:error, reason}
    end
  end

  defp verify_digest(record, digest) do
    if Anchor.digest(record) == digest do
      :ok
    else
      {:error, :digest_mismatch}
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
        case digest_from_uri(receipt_uri(receipt)) do
          digest when is_binary(digest) -> digest_from_ref(digest)
          _ -> {:error, :missing_digest}
        end
    end
  end

  defp digest_from_ref(_), do: {:error, :missing_digest}

  defp validate_uri_digest(receipt, digest) do
    case digest_from_uri(receipt_uri(receipt)) do
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

  defp digest_from_uri(uri) when is_binary(uri) do
    uri
    |> URI.parse()
    |> Map.get(:fragment)
  end

  defp digest_from_uri(_), do: nil

  defp receipt_uri(%{} = receipt), do: field(receipt, "uri")
  defp receipt_uri(_), do: nil

  defp location_header(headers) do
    Enum.find_value(headers, fn {key, value} ->
      if String.downcase(key) == "location", do: value
    end)
  end

  defp join_url(base, path) do
    String.trim_trailing(base, "/") <> "/" <> String.trim_leading(path, "/")
  end

  defp replace_digest(path, digest),
    do: String.replace(path, ":digest", URI.encode_www_form(digest))

  defp timeout(opts) do
    case Keyword.get(opts, :timeout, @default_timeout_ms) do
      timeout when is_integer(timeout) and timeout >= 0 -> {:ok, timeout}
      :infinity -> {:ok, :infinity}
      _ -> {:error, :invalid_timeout}
    end
  end

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

  defp nonempty_binary?(value), do: is_binary(value) and value != ""

  defp timestamp do
    DateTime.utc_now(:millisecond)
    |> DateTime.to_iso8601()
  end
end
