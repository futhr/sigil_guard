defmodule SigilGuard.Audit.Anchor.Receipt do
  @moduledoc """
  Signing and verification helpers for external audit anchor receipts.

  Anchor stores return compact receipt maps that point back to an externally
  persisted audit anchor. This module defines the canonical receipt bytes used
  for receipt digests and Ed25519 provenance, so remote WORM/append-only
  services can produce receipts that `SigilGuard.Audit.Anchor.Store.HTTP`
  verifies in strict mode.

  Top-level `"signature"` metadata is excluded from canonical bytes, matching
  the checkpoint and compatibility-bundle signing pattern.
  """

  @signature_algorithm "Ed25519"
  @metadata_keys ~w(signature)
  @metadata_atom_keys [:signature]
  @atom_fields %{
    "algorithm" => :algorithm,
    "digest" => :digest,
    "issuer" => :issuer,
    "signature" => :signature
  }

  @typedoc "Store-specific persistence receipt for an anchor record."
  @type t :: %{required(String.t()) => term()}

  @doc """
  Return canonical receipt bytes, excluding top-level signature metadata.
  """
  @spec canonical_bytes(map()) :: binary()
  def canonical_bytes(receipt) when is_map(receipt) do
    receipt
    |> unsigned()
    |> canonical_iodata()
    |> IO.iodata_to_binary()
  end

  @doc """
  Return the lowercase SHA-256 digest of canonical receipt bytes.
  """
  @spec digest(map()) :: String.t()
  def digest(receipt) when is_map(receipt) do
    receipt
    |> canonical_bytes()
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end

  @doc """
  Return the receipt without top-level signature metadata.
  """
  @spec unsigned(map()) :: map()
  def unsigned(receipt) when is_map(receipt),
    do: Map.drop(receipt, @metadata_keys ++ @metadata_atom_keys)

  @doc """
  Sign a receipt using a `SigilGuard.Signer` module.

  Options:

    * `:issuer` - required receipt issuer identifier, usually a DID.
  """
  @spec sign(map(), module(), keyword()) :: map()
  def sign(receipt, signer, opts) when is_map(receipt) and is_atom(signer) and is_list(opts) do
    issuer = Keyword.fetch!(opts, :issuer)
    unsigned_receipt = unsigned(receipt)

    signature =
      unsigned_receipt
      |> canonical_bytes()
      |> signer.sign()

    Map.put(unsigned_receipt, "signature", %{
      "issuer" => issuer,
      "algorithm" => @signature_algorithm,
      "digest" => digest(unsigned_receipt),
      "signature" => Base.url_encode64(signature, padding: false)
    })
  end

  @doc """
  Verify signed receipt provenance.

  Options:

    * `:public_keys` - map of issuer to base64/base64url Ed25519 public key.
    * `:public_key_b64u` - fallback public key for any issuer.
  """
  @spec verify(map(), keyword()) :: :ok | {:error, atom()}
  def verify(receipt, opts \\ [])

  def verify(receipt, opts) when is_map(receipt) and is_list(opts) do
    case signature(receipt) do
      signature when is_map(signature) -> verify_signature(receipt, signature, opts)
      nil -> {:error, :unsigned_receipt}
      _ -> {:error, :invalid_signature_metadata}
    end
  end

  def verify(_, _), do: {:error, :invalid_receipt}

  @doc """
  Return top-level signature metadata from a string-keyed or atom-keyed receipt.
  """
  @spec signature(map()) :: map() | term() | nil
  def signature(receipt) when is_map(receipt) do
    case Map.fetch(receipt, "signature") do
      {:ok, signature} -> signature
      :error -> Map.get(receipt, :signature)
    end
  end

  defp verify_signature(receipt, signature, opts) do
    with {:ok, fields} <- signature_fields(signature),
         :ok <- validate_signature_digest(receipt, fields.digest),
         {:ok, public_key} <- public_key(fields.issuer, opts),
         {:ok, decoded_signature} <- decode_signature(fields.signature) do
      verify_ed25519(receipt, decoded_signature, public_key)
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
         :ok <- require_binary(fields.algorithm, :missing_algorithm),
         :ok <- require_algorithm(fields.algorithm),
         :ok <- require_binary(fields.digest, :missing_digest),
         :ok <- require_binary(fields.signature, :missing_signature) do
      {:ok, fields}
    end
  end

  defp require_binary(value, _) when is_binary(value) and value != "", do: :ok
  defp require_binary(_, reason), do: {:error, reason}

  defp require_algorithm(@signature_algorithm), do: :ok
  defp require_algorithm(_), do: {:error, :unsupported_algorithm}

  defp validate_signature_digest(receipt, claimed_digest) do
    if secure_compare(digest(receipt), claimed_digest) do
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

  defp verify_ed25519(receipt, signature, public_key) do
    if :crypto.verify(:eddsa, :none, canonical_bytes(receipt), signature, [public_key, :ed25519]) do
      :ok
    else
      {:error, :invalid_signature}
    end
  rescue
    ErlangError -> {:error, :invalid_signature}
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

  defp secure_compare(a, b) when is_binary(a) and is_binary(b) and byte_size(a) == byte_size(b) do
    secure_compare(a, b, 0)
  end

  defp secure_compare(_, _), do: false

  defp secure_compare(<<a, rest_a::binary>>, <<b, rest_b::binary>>, diff) do
    secure_compare(rest_a, rest_b, Bitwise.bor(diff, Bitwise.bxor(a, b)))
  end

  defp secure_compare(<<>>, <<>>, diff), do: diff == 0
end
