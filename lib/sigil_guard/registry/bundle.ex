defmodule SigilGuard.Registry.Bundle do
  @moduledoc """
  Pattern-bundle provenance, digesting, signing, and quarantine checks.

  Registry bundles are executable scanner configuration. This module gives
  registry consumers a deterministic provenance boundary:

    * canonical bundle bytes exclude top-level provenance/signature metadata
    * digests are SHA-256 over canonical bytes
    * signatures are Ed25519 signatures over canonical bytes
    * invalid signed bundles return quarantine metadata instead of patterns

  Unsigned bundles are accepted by default for compatibility with older
  registries. Set `require_signature: true` when a deployment has configured
  trusted bundle public keys.
  """

  @metadata_keys ~w(provenance signature signatures)
  @metadata_atom_keys [:provenance, :signature, :signatures]
  @signature_algorithm "Ed25519"

  @type status :: :verified | :unsigned

  @type verified :: %{
          bundle: map(),
          status: status(),
          digest: String.t(),
          issuer: String.t() | nil,
          provenance: map() | nil
        }

  @type quarantine :: %{
          reason: atom(),
          digest: String.t() | nil,
          issuer: String.t() | nil,
          provenance: map() | nil
        }

  @doc """
  Return canonical bytes for a bundle, excluding top-level provenance fields.
  """
  @spec canonical_bytes(map()) :: binary()
  def canonical_bytes(bundle) when is_map(bundle) do
    bundle
    |> unsigned_bundle()
    |> canonical_iodata()
    |> IO.iodata_to_binary()
  end

  @doc """
  Return the lowercase SHA-256 digest of a bundle's canonical bytes.
  """
  @spec digest(map()) :: String.t()
  def digest(bundle) when is_map(bundle) do
    hash = :crypto.hash(:sha256, canonical_bytes(bundle))
    Base.encode16(hash, case: :lower)
  end

  @doc """
  Sign a registry bundle using a `SigilGuard.Signer` module.

  Options:

    * `:issuer` - required issuer identifier, usually a DID.
    * `:issued_at` - optional ISO 8601 timestamp, defaults to current UTC time.
    * `:expires_at` - optional ISO 8601 timestamp after which verifiers quarantine the bundle.
  """
  @spec sign(map(), module(), keyword()) :: map()
  def sign(bundle, signer, opts) when is_map(bundle) do
    issuer = Keyword.fetch!(opts, :issuer)
    issued_at = Keyword.get_lazy(opts, :issued_at, &timestamp/0)
    expires_at = Keyword.get(opts, :expires_at)
    unsigned = unsigned_bundle(bundle)
    signature = signer.sign(canonical_bytes(unsigned))

    provenance =
      %{
        "issuer" => issuer,
        "issued_at" => issued_at,
        "algorithm" => @signature_algorithm,
        "digest" => digest(unsigned),
        "signature" => Base.url_encode64(signature, padding: false)
      }
      |> put_optional("expires_at", expires_at)

    Map.put(unsigned, "provenance", provenance)
  end

  @doc """
  Verify bundle provenance and return either a verified bundle or quarantine.

  Options:

    * `:public_keys` - map of issuer to base64/base64url Ed25519 public key.
    * `:public_key_b64u` - fallback public key for any issuer.
    * `:require_signature` - quarantine unsigned bundles when true.
    * `:max_age_seconds` - quarantine signed bundles older than this many seconds.
    * `:clock_skew_seconds` - allowed future `issued_at` skew, defaults to 60.
    * `:now` - verification clock as a `DateTime` or ISO 8601 timestamp, defaults to current UTC time.
  """
  @spec verify(map(), keyword()) :: {:ok, verified()} | {:quarantine, quarantine()}
  def verify(bundle, opts \\ [])

  def verify(bundle, opts) when is_map(bundle) and is_list(opts) do
    case Map.get(bundle, "provenance") || Map.get(bundle, :provenance) do
      nil -> verify_unsigned(bundle, opts)
      provenance when is_map(provenance) -> verify_signed(bundle, provenance, opts)
      _ -> quarantine(:invalid_provenance, bundle, nil)
    end
  end

  def verify(_, _), do: {:quarantine, quarantine_map(:invalid_bundle, nil, nil)}

  defp verify_unsigned(bundle, opts) do
    if Keyword.get(opts, :require_signature, false) do
      quarantine(:unsigned_bundle, bundle, nil)
    else
      {:ok,
       %{
         bundle: unsigned_bundle(bundle),
         status: :unsigned,
         digest: digest(bundle),
         issuer: nil,
         provenance: nil
       }}
    end
  end

  defp verify_signed(bundle, provenance, opts) do
    with {:ok, fields} <- provenance_fields(provenance),
         :ok <- validate_digest(bundle, fields.digest),
         :ok <- validate_time_bounds(fields, opts),
         {:ok, public_key} <- public_key(fields.issuer, opts),
         {:ok, signature} <- decode_signature(fields.signature),
         :ok <- verify_signature(bundle, signature, public_key) do
      {:ok,
       %{
         bundle: unsigned_bundle(bundle),
         status: :verified,
         digest: fields.digest,
         issuer: fields.issuer,
         provenance: provenance
       }}
    else
      {:error, reason} -> quarantine(reason, bundle, provenance)
    end
  end

  defp provenance_fields(%{} = provenance) do
    fields = %{
      issuer: provenance["issuer"] || provenance[:issuer],
      algorithm: provenance["algorithm"] || provenance[:algorithm],
      digest: provenance["digest"] || provenance[:digest],
      signature: provenance["signature"] || provenance[:signature],
      issued_at: provenance["issued_at"] || provenance[:issued_at],
      expires_at: provenance["expires_at"] || provenance[:expires_at]
    }

    with :ok <- require_binary(fields.issuer, :missing_issuer),
         :ok <- require_binary(fields.algorithm, :missing_algorithm),
         :ok <- require_algorithm(fields.algorithm),
         :ok <- require_binary(fields.digest, :missing_digest),
         :ok <- require_binary(fields.signature, :missing_signature) do
      {:ok, fields}
    end
  end

  defp require_binary(value, _) when is_binary(value), do: :ok
  defp require_binary(_, reason), do: {:error, reason}

  defp require_algorithm(@signature_algorithm), do: :ok
  defp require_algorithm(_), do: {:error, :unsupported_algorithm}

  defp validate_digest(bundle, claimed_digest) do
    if secure_compare(digest(bundle), claimed_digest), do: :ok, else: {:error, :digest_mismatch}
  end

  defp validate_time_bounds(fields, opts) do
    with {:ok, issued_at} <- optional_datetime(fields.issued_at, :invalid_issued_at),
         {:ok, expires_at} <- optional_datetime(fields.expires_at, :invalid_expires_at),
         {:ok, now} <- verification_now(opts),
         {:ok, bounds} <- time_bounds(opts),
         :ok <- validate_expiration(expires_at, now),
         :ok <- validate_issued_at(issued_at, now, bounds.clock_skew_seconds) do
      validate_max_age(issued_at, now, bounds.max_age_seconds)
    end
  end

  defp time_bounds(opts) do
    max_age_seconds = Keyword.get(opts, :max_age_seconds)
    clock_skew_seconds = Keyword.get(opts, :clock_skew_seconds, 60)

    cond do
      not valid_seconds?(max_age_seconds, true) -> {:error, :invalid_max_age}
      not valid_seconds?(clock_skew_seconds, false) -> {:error, :invalid_clock_skew}
      true -> {:ok, %{max_age_seconds: max_age_seconds, clock_skew_seconds: clock_skew_seconds}}
    end
  end

  defp valid_seconds?(nil, true), do: true
  defp valid_seconds?(value, _), do: is_integer(value) and value >= 0

  defp validate_expiration(nil, _), do: :ok

  defp validate_expiration(expires_at, now) do
    if DateTime.compare(expires_at, now) == :gt, do: :ok, else: {:error, :expired_bundle}
  end

  defp validate_issued_at(nil, _, _), do: :ok

  defp validate_issued_at(issued_at, now, clock_skew_seconds) do
    if DateTime.diff(issued_at, now, :second) > clock_skew_seconds do
      {:error, :future_issued_at}
    else
      :ok
    end
  end

  defp validate_max_age(nil, _, nil), do: :ok
  defp validate_max_age(nil, _, _), do: {:error, :missing_issued_at}
  defp validate_max_age(_, _, nil), do: :ok

  defp validate_max_age(issued_at, now, max_age_seconds) do
    if DateTime.diff(now, issued_at, :second) > max_age_seconds do
      {:error, :stale_bundle}
    else
      :ok
    end
  end

  defp optional_datetime(nil, _), do: {:ok, nil}

  defp optional_datetime(value, reason) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _} -> {:ok, datetime}
      {:error, _} -> {:error, reason}
    end
  end

  defp optional_datetime(_, reason), do: {:error, reason}

  defp verification_now(opts) do
    case Keyword.get_lazy(opts, :now, fn -> DateTime.utc_now(:second) end) do
      %DateTime{} = now -> {:ok, now}
      value when is_binary(value) -> optional_datetime(value, :invalid_now)
      _ -> {:error, :invalid_now}
    end
  end

  defp public_key(issuer, opts) do
    public_keys = Keyword.get(opts, :public_keys, %{})

    encoded =
      public_keys[issuer] || public_keys[to_string(issuer)] || Keyword.get(opts, :public_key_b64u)

    case encoded do
      value when is_binary(value) -> decode_public_key(value)
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

  defp verify_signature(bundle, signature, public_key) do
    try do
      if :crypto.verify(:eddsa, :none, canonical_bytes(bundle), signature, [public_key, :ed25519]) do
        :ok
      else
        {:error, :invalid_signature}
      end
    rescue
      ErlangError -> {:error, :invalid_signature}
    end
  end

  defp unsigned_bundle(bundle) do
    Map.drop(bundle, @metadata_keys ++ @metadata_atom_keys)
  end

  defp put_optional(map, _, nil), do: map
  defp put_optional(map, key, value), do: Map.put(map, key, value)

  defp quarantine(reason, bundle, provenance) do
    {:quarantine, quarantine_map(reason, bundle, provenance)}
  end

  defp quarantine_map(reason, bundle, provenance) do
    %{
      reason: reason,
      digest: digest_or_nil(bundle),
      issuer: issuer(provenance),
      provenance: provenance
    }
  end

  defp digest_or_nil(bundle) when is_map(bundle), do: digest(bundle)
  defp digest_or_nil(_), do: nil

  defp issuer(%{} = provenance), do: provenance["issuer"] || provenance[:issuer]
  defp issuer(_), do: nil

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

  defp timestamp do
    now = DateTime.utc_now(:millisecond)
    DateTime.to_iso8601(now)
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
