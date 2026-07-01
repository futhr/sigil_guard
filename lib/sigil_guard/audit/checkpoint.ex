defmodule SigilGuard.Audit.Checkpoint do
  @moduledoc """
  Portable checkpoints for signed audit chains.

  `SigilGuard.Audit` protects each local event chain with an HMAC link, but
  events alone cannot prove that the tail has not been truncated. Checkpoints
  summarize a chain or chain segment into a deterministic record that can be
  signed, exported, and stored in an external append-only or WORM system.

  A checkpoint contains:

    * event count and first/last event identifiers
    * first/last HMACs and the segment's previous HMAC anchor
    * an ordered SHA-256 Merkle root over event HMACs
    * optional deployment metadata and external anchor details
    * optional Ed25519 signature over canonical checkpoint bytes

  The signature and digest cover the checkpoint fields, not the raw event
  bodies. This makes checkpoints safe to anchor in external systems without
  leaking audit metadata.
  """

  alias SigilGuard.Audit

  @kind "sigil_guard.audit.checkpoint"
  @version 1
  @algorithm "sha256-merkle-v1"
  @signature_algorithm "Ed25519"
  @empty_root_input "sigil-audit-empty-v1"
  @leaf_prefix "sigil-audit-leaf-v1:"
  @node_prefix "sigil-audit-node-v1:"
  @metadata_keys ~w(signature)
  @metadata_atom_keys [:signature]
  @atom_fields %{
    "algorithm" => :algorithm,
    "chain_id" => :chain_id,
    "digest" => :digest,
    "event_count" => :event_count,
    "first_event_id" => :first_event_id,
    "first_hmac" => :first_hmac,
    "generated_at" => :generated_at,
    "issuer" => :issuer,
    "kind" => :kind,
    "last_event_id" => :last_event_id,
    "last_hmac" => :last_hmac,
    "merkle_root" => :merkle_root,
    "prev_hmac" => :prev_hmac,
    "signature" => :signature,
    "version" => :version
  }

  @type status :: :verified | :unsigned
  @type t :: map()

  @type verified :: %{
          checkpoint: t(),
          status: status(),
          digest: String.t(),
          issuer: String.t() | nil
        }

  @doc """
  Create an unsigned checkpoint for a signed audit chain or continuation segment.

  Options:

    * `:prev_hmac` - expected previous HMAC for a continuation segment.
    * `:chain_id` - optional stable identifier for the logical audit chain.
    * `:metadata` - optional JSON-compatible metadata for operators.
    * `:anchor` - optional external anchor/WORM location metadata.
    * `:generated_at` - optional ISO 8601 timestamp, defaults to current UTC.
  """
  @spec create([Audit.t()], keyword()) :: {:ok, t()} | {:error, atom()}
  def create(events, opts \\ [])

  def create(events, opts) when is_list(events) and is_list(opts) do
    prev_hmac = Keyword.get(opts, :prev_hmac)

    with {:ok, generated_at} <- generated_at(opts),
         {:ok, metadata} <- metadata(opts),
         {:ok, anchor} <- anchor(opts),
         :ok <- validate_links(events, prev_hmac),
         {:ok, root} <- merkle_root(events) do
      {:ok,
       base_checkpoint(events, root, %{
         prev_hmac: prev_hmac,
         chain_id: Keyword.get(opts, :chain_id),
         metadata: metadata,
         anchor: anchor,
         generated_at: generated_at
       })}
    end
  end

  def create(_, _), do: {:error, :invalid_events}

  @doc """
  Return the ordered Merkle root for a list of signed audit events.

  The root is calculated over event HMACs only, with domain-separated SHA-256
  leaf and node hashes. Odd nodes are promoted to the next level, avoiding the
  duplicate-last-leaf ambiguity common in simpler Merkle tree implementations.
  """
  @spec merkle_root([Audit.t()]) :: {:ok, String.t()} | {:error, atom()}
  def merkle_root(events) when is_list(events) do
    with {:ok, leaves} <- leaf_hashes(events) do
      root =
        leaves
        |> root_hash()
        |> Base.encode16(case: :lower)

      {:ok, root}
    end
  end

  def merkle_root(_), do: {:error, :invalid_events}

  @doc """
  Return canonical checkpoint bytes used for digesting and signatures.

  Top-level signature metadata is excluded so a signed checkpoint verifies
  against the same canonical bytes as the unsigned checkpoint.
  """
  @spec canonical_bytes(t()) :: binary()
  def canonical_bytes(checkpoint) when is_map(checkpoint) do
    checkpoint
    |> unsigned_checkpoint()
    |> canonical_iodata()
    |> IO.iodata_to_binary()
  end

  @doc """
  Return the lowercase SHA-256 digest of canonical checkpoint bytes.
  """
  @spec digest(t()) :: String.t()
  def digest(checkpoint) when is_map(checkpoint) do
    hash = :crypto.hash(:sha256, canonical_bytes(checkpoint))
    Base.encode16(hash, case: :lower)
  end

  @doc """
  Sign a checkpoint with an Ed25519 `SigilGuard.Signer` module.

  Options:

    * `:issuer` - required issuer identifier, usually a DID.
    * `:issued_at` - optional ISO 8601 timestamp, defaults to current UTC.
  """
  @spec sign(t(), module(), keyword()) :: t()
  def sign(checkpoint, signer, opts) when is_map(checkpoint) and is_atom(signer) do
    issuer = Keyword.fetch!(opts, :issuer)
    issued_at = Keyword.get_lazy(opts, :issued_at, &timestamp/0)
    unsigned = unsigned_checkpoint(checkpoint)
    signature = signer.sign(canonical_bytes(unsigned))

    Map.put(unsigned, "signature", %{
      "algorithm" => @signature_algorithm,
      "issuer" => issuer,
      "issued_at" => issued_at,
      "digest" => digest(unsigned),
      "signature" => Base.url_encode64(signature, padding: false)
    })
  end

  @doc """
  Verify that a checkpoint matches the supplied events and optional signature.

  Options:

    * `:public_keys` - map of issuer to base64/base64url Ed25519 public key.
    * `:public_key_b64u` - fallback public key for any issuer.
    * `:require_signature` - reject unsigned checkpoints when true.
  """
  @spec verify(t(), [Audit.t()], keyword()) :: {:ok, verified()} | {:error, atom()}
  def verify(checkpoint, events, opts \\ [])

  def verify(checkpoint, events, opts)
      when is_map(checkpoint) and is_list(events) and is_list(opts) do
    with :ok <- verify_static_fields(checkpoint),
         {:ok, prev_hmac} <- checkpoint_prev_hmac(checkpoint),
         :ok <- validate_links(events, prev_hmac),
         :ok <- verify_event_summary(checkpoint, events),
         {:ok, signature_status} <- verify_signature_status(checkpoint, opts) do
      {:ok,
       %{
         checkpoint: unsigned_checkpoint(checkpoint),
         status: signature_status.status,
         digest: digest(checkpoint),
         issuer: signature_status.issuer
       }}
    end
  end

  def verify(_, _, _), do: {:error, :invalid_checkpoint}

  defp base_checkpoint(events, root, attrs) do
    {first_event, last_event} = endpoints(events)

    %{
      "kind" => @kind,
      "version" => @version,
      "algorithm" => @algorithm,
      "generated_at" => attrs.generated_at,
      "chain_id" => attrs.chain_id,
      "event_count" => length(events),
      "prev_hmac" => attrs.prev_hmac,
      "first_event_id" => event_field(first_event, :id),
      "last_event_id" => event_field(last_event, :id),
      "first_hmac" => event_field(first_event, :hmac),
      "last_hmac" => event_field(last_event, :hmac),
      "merkle_root" => root,
      "metadata" => attrs.metadata,
      "anchor" => attrs.anchor
    }
  end

  defp endpoints([]), do: {nil, nil}
  defp endpoints(events), do: {List.first(events), List.last(events)}

  defp event_field(nil, _), do: nil
  defp event_field(%Audit{} = event, key), do: Map.fetch!(event, key)

  defp verify_static_fields(checkpoint) do
    with :ok <- require_field(checkpoint, "kind", @kind, :invalid_kind),
         :ok <- require_field(checkpoint, "version", @version, :invalid_version),
         :ok <- require_field(checkpoint, "algorithm", @algorithm, :invalid_algorithm),
         :ok <- require_binary(field(checkpoint, "generated_at"), :missing_generated_at),
         :ok <- require_integer(field(checkpoint, "event_count"), :missing_event_count) do
      require_binary(field(checkpoint, "merkle_root"), :missing_merkle_root)
    end
  end

  defp require_field(checkpoint, key, value, reason) do
    if field(checkpoint, key) == value, do: :ok, else: {:error, reason}
  end

  defp require_binary(value, _) when is_binary(value) and value != "", do: :ok
  defp require_binary(_, reason), do: {:error, reason}

  defp require_integer(value, _) when is_integer(value) and value >= 0, do: :ok
  defp require_integer(_, reason), do: {:error, reason}

  defp generated_at(opts) do
    case Keyword.get_lazy(opts, :generated_at, &timestamp/0) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, :invalid_generated_at}
    end
  end

  defp metadata(opts) do
    case Keyword.get(opts, :metadata, %{}) do
      metadata when is_map(metadata) -> {:ok, metadata}
      _ -> {:error, :invalid_metadata}
    end
  end

  defp anchor(opts) do
    case Keyword.get(opts, :anchor, %{}) do
      anchor when is_map(anchor) -> {:ok, anchor}
      _ -> {:error, :invalid_anchor_metadata}
    end
  end

  defp checkpoint_prev_hmac(checkpoint) do
    case field(checkpoint, "prev_hmac") do
      nil -> {:ok, nil}
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, :invalid_prev_hmac}
    end
  end

  defp verify_event_summary(checkpoint, events) do
    with {:ok, root} <- merkle_root(events),
         true <- field(checkpoint, "event_count") == length(events),
         true <- field(checkpoint, "merkle_root") == root,
         true <- endpoints_match?(checkpoint, events) do
      :ok
    else
      {:error, reason} -> {:error, reason}
      false -> {:error, :checkpoint_mismatch}
    end
  end

  defp endpoints_match?(checkpoint, events) do
    {first_event, last_event} = endpoints(events)

    field(checkpoint, "first_event_id") == event_field(first_event, :id) and
      field(checkpoint, "last_event_id") == event_field(last_event, :id) and
      field(checkpoint, "first_hmac") == event_field(first_event, :hmac) and
      field(checkpoint, "last_hmac") == event_field(last_event, :hmac)
  end

  defp verify_signature_status(checkpoint, opts) do
    case field(checkpoint, "signature") do
      nil -> verify_unsigned(opts)
      signature when is_map(signature) -> verify_signed(checkpoint, signature, opts)
      _ -> {:error, :invalid_signature_metadata}
    end
  end

  defp verify_unsigned(opts) do
    if Keyword.get(opts, :require_signature, false) do
      {:error, :unsigned_checkpoint}
    else
      {:ok, %{status: :unsigned, issuer: nil}}
    end
  end

  defp verify_signed(checkpoint, signature, opts) do
    with {:ok, fields} <- signature_fields(signature),
         :ok <- validate_signature_digest(checkpoint, fields.digest),
         {:ok, public_key} <- public_key(fields.issuer, opts),
         {:ok, decoded_signature} <- decode_signature(fields.signature),
         :ok <- verify_ed25519(checkpoint, decoded_signature, public_key) do
      {:ok, %{status: :verified, issuer: fields.issuer}}
    end
  end

  defp signature_fields(%{} = signature) do
    fields = %{
      issuer: field(signature, "issuer"),
      algorithm: field(signature, "algorithm"),
      digest: field(signature, "digest"),
      signature: field(signature, "signature")
    }

    with :ok <- require_binary(fields.issuer, :missing_issuer),
         :ok <-
           require_field(signature, "algorithm", @signature_algorithm, :unsupported_algorithm),
         :ok <- require_binary(fields.digest, :missing_digest),
         :ok <- require_binary(fields.signature, :missing_signature) do
      {:ok, fields}
    end
  end

  defp validate_signature_digest(checkpoint, claimed_digest) do
    if secure_compare(digest(checkpoint), claimed_digest) do
      :ok
    else
      {:error, :digest_mismatch}
    end
  end

  defp public_key(issuer, opts) do
    public_keys = Keyword.get(opts, :public_keys, %{})

    if is_map(public_keys) do
      with {:ok, encoded} <- public_key_source(public_keys, issuer, opts) do
        decode_public_key(encoded)
      end
    else
      {:error, :invalid_public_keys}
    end
  end

  defp public_key_source(public_keys, issuer, opts) do
    case fetch_issuer_public_key(public_keys, issuer) do
      {:ok, value} when is_binary(value) -> {:ok, value}
      {:ok, _} -> {:error, :invalid_key}
      :error -> fallback_public_key(opts)
    end
  end

  defp fetch_issuer_public_key(public_keys, issuer) do
    Enum.reduce_while([issuer, to_string(issuer)], :error, fn key, :error ->
      case Map.fetch(public_keys, key) do
        {:ok, value} -> {:halt, {:ok, value}}
        :error -> {:cont, :error}
      end
    end)
  end

  defp fallback_public_key(opts) do
    case Keyword.get(opts, :public_key_b64u) do
      value when is_binary(value) -> {:ok, value}
      _ -> {:error, :unknown_issuer}
    end
  end

  defp decode_public_key(value) do
    case decode_base64(value) do
      key when is_binary(key) and byte_size(key) == 32 -> {:ok, key}
      key when is_binary(key) -> {:error, :invalid_key}
      nil -> {:error, :invalid_base64}
    end
  end

  defp decode_signature(value) do
    case decode_base64(value) do
      signature when is_binary(signature) and byte_size(signature) == 64 -> {:ok, signature}
      signature when is_binary(signature) -> {:error, :invalid_signature}
      nil -> {:error, :invalid_base64}
    end
  end

  defp verify_ed25519(checkpoint, signature, public_key) do
    if :crypto.verify(:eddsa, :none, canonical_bytes(checkpoint), signature, [
         public_key,
         :ed25519
       ]) do
      :ok
    else
      {:error, :invalid_signature}
    end
  rescue
    ErlangError -> {:error, :invalid_signature}
  end

  defp decode_base64(value) do
    case decode_url64(value) do
      nil -> decode_64(value)
      decoded -> decoded
    end
  end

  defp decode_url64(value) do
    with :error <- Base.url_decode64(value, padding: false),
         :error <- Base.url_decode64(value, padding: true) do
      nil
    else
      {:ok, decoded} -> decoded
    end
  end

  defp decode_64(value) do
    with :error <- Base.decode64(value, padding: false),
         :error <- Base.decode64(value, padding: true) do
      nil
    else
      {:ok, decoded} -> decoded
    end
  end

  defp validate_links([], nil), do: :ok
  defp validate_links([], prev_hmac) when is_binary(prev_hmac) and prev_hmac != "", do: :ok
  defp validate_links([], _), do: {:error, :invalid_prev_hmac}

  defp validate_links([first | rest], prev_hmac)
       when is_nil(prev_hmac) or (is_binary(prev_hmac) and prev_hmac != "") do
    if first.prev_hmac == prev_hmac and signed_event?(first) do
      validate_next_links(rest, first.hmac)
    else
      {:error, :broken_chain}
    end
  end

  defp validate_links(_, _), do: {:error, :invalid_prev_hmac}

  defp validate_next_links([], _), do: :ok

  defp validate_next_links([event | rest], prev_hmac) do
    if event.prev_hmac == prev_hmac and signed_event?(event) do
      validate_next_links(rest, event.hmac)
    else
      {:error, :broken_chain}
    end
  end

  defp signed_event?(%Audit{hmac: hmac}) when is_binary(hmac) and byte_size(hmac) > 0, do: true
  defp signed_event?(_), do: false

  defp leaf_hashes(events) do
    result =
      Enum.reduce_while(events, {:ok, []}, fn
        %Audit{hmac: hmac}, {:ok, acc} when is_binary(hmac) and byte_size(hmac) > 0 ->
          {:cont, {:ok, [:crypto.hash(:sha256, [@leaf_prefix, hmac]) | acc]}}

        _, _ ->
          {:halt, {:error, :unsigned_event}}
      end)

    case result do
      {:ok, leaves} -> {:ok, Enum.reverse(leaves)}
      error -> error
    end
  end

  defp root_hash([]), do: :crypto.hash(:sha256, @empty_root_input)
  defp root_hash([root]), do: root

  defp root_hash(nodes) do
    nodes
    |> pair_level([])
    |> root_hash()
  end

  defp pair_level([], acc), do: Enum.reverse(acc)
  defp pair_level([node], acc), do: Enum.reverse([node | acc])

  defp pair_level([left, right | rest], acc) do
    pair_level(rest, [:crypto.hash(:sha256, [@node_prefix, left, right]) | acc])
  end

  defp unsigned_checkpoint(checkpoint) do
    Map.drop(checkpoint, @metadata_keys ++ @metadata_atom_keys)
  end

  defp canonical_iodata(value) when is_map(value) do
    parts =
      value
      |> Enum.map(fn {key, item} -> {canonical_key(key), item} end)
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.map(fn {key, item} -> [Jason.encode!(key), ?:, canonical_iodata(item)] end)
      |> Enum.intersperse(",")

    [?{, parts, ?}]
  end

  defp canonical_iodata(value) when is_list(value) do
    parts =
      value
      |> Enum.map(&canonical_iodata/1)
      |> Enum.intersperse(",")

    [?[, parts, ?]]
  end

  defp canonical_iodata(value)
       when is_atom(value) and not is_boolean(value) and not is_nil(value) do
    value
    |> Atom.to_string()
    |> Jason.encode!()
  end

  defp canonical_iodata(value), do: Jason.encode!(value)

  defp canonical_key(key) when is_atom(key), do: Atom.to_string(key)
  defp canonical_key(key) when is_binary(key), do: key
  defp canonical_key(key), do: to_string(key)

  defp field(map, key) when is_map(map) do
    case Map.fetch(map, key) do
      {:ok, value} -> value
      :error -> Map.get(map, Map.fetch!(@atom_fields, key))
    end
  end

  defp timestamp do
    DateTime.utc_now(:millisecond)
    |> DateTime.to_iso8601()
  end

  defp secure_compare(a, b) when is_binary(a) and is_binary(b) and byte_size(a) == byte_size(b) do
    secure_compare(a, b, 0)
  end

  defp secure_compare(_, _), do: false

  defp secure_compare(<<a, rest_a::binary>>, <<b, rest_b::binary>>, diff) do
    secure_compare(rest_a, rest_b, Bitwise.bor(diff, Bitwise.bxor(a, b)))
  end

  defp secure_compare(<<>>, <<>>, diff), do: diff == 0
end
