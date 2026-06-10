defmodule SigilGuard.Envelope do
  @moduledoc """
  SIGIL envelope implementation for MCP JSON-RPC `_sigil` metadata.

  Implements the envelope format defined by the SIGIL protocol:
  - Canonical bytes: lexicographic key order, compact JSON, no whitespace,
    excluding `signature` and `reason`
  - Ed25519 signature, base64url-encoded (no padding)
  - ISO 8601 timestamp with millisecond precision (UTC)
  - 16-byte cryptographically random nonce, hex-encoded

  ## Signing

  Signing requires a module implementing `SigilGuard.Signer`:

      envelope = SigilGuard.Envelope.sign("did:sigil:abc", :allowed, signer: MySigner)

  ## Verification

      :ok = SigilGuard.Envelope.verify(envelope, public_key_b64u)

  """

  @type verdict :: :allowed | :blocked | :scanned

  @type t :: %{
          required(String.t()) => String.t()
        }

  @canonical_keys ~w(identity nonce timestamp verdict)

  @doc """
  Produce the canonical byte representation for signing.

  Fields are serialized as compact JSON with lexicographic key order,
  no whitespace, excluding `signature` and `reason`. This matches the
  Rust `sigil-protocol` crate's `canonical_bytes` implementation.
  """
  @spec canonical_bytes(String.t(), verdict(), String.t(), String.t()) :: binary()
  def canonical_bytes(identity, verdict, timestamp, nonce_hex) do
    %{
      "identity" => identity,
      "nonce" => nonce_hex,
      "timestamp" => timestamp,
      "verdict" => canonical_verdict(verdict)
    }
    |> then(fn fields ->
      parts =
        @canonical_keys
        |> Enum.map(fn key -> [?", key, ?", ?:, Jason.encode!(fields[key])] end)
        |> Enum.intersperse(",")

      IO.iodata_to_binary([?{, parts, ?}])
    end)
  end

  @doc """
  Sign an envelope with the given identity and verdict.

  ## Options

    * `:signer` — module implementing `SigilGuard.Signer` (required)
    * `:reason` — optional human-readable reason string
    * `:timestamp` — override timestamp (for testing)
    * `:nonce` — override nonce hex (for testing)

  Returns a map suitable for embedding as the `_sigil` field in MCP JSON-RPC params.
  """
  @spec sign(String.t(), verdict(), keyword()) :: t()
  def sign(identity, verdict, opts) do
    signer = Keyword.fetch!(opts, :signer)
    reason = Keyword.get(opts, :reason)
    timestamp = Keyword.get_lazy(opts, :timestamp, &generate_timestamp/0)
    nonce_hex = Keyword.get_lazy(opts, :nonce, &generate_nonce/0)

    bytes = canonical_bytes(identity, verdict, timestamp, nonce_hex)
    signature = signer.sign(bytes)
    signature_b64u = Base.url_encode64(signature, padding: false)

    envelope = %{
      "identity" => identity,
      "verdict" => format_verdict(verdict),
      "timestamp" => timestamp,
      "nonce" => nonce_hex,
      "signature" => signature_b64u
    }

    if reason, do: Map.put(envelope, "reason", reason), else: envelope
  end

  @doc """
  Verify an envelope's signature against a base64url-encoded Ed25519 public key.

  Returns `:ok` if the signature is valid, or `{:error, reason}` otherwise.
  Never raises on malformed input — envelopes arrive over the wire and
  must be treated as adversarial.

  ## Error reasons

    * `:invalid_envelope` — envelope is not a map, or the key is not a string
    * `:missing_field` — a required field (`identity`, `verdict`, `timestamp`,
      `nonce`, `signature`) is absent or not a string
    * `:invalid_verdict` — verdict is not `"Allowed"`, `"Blocked"`, or `"Scanned"`
    * `:invalid_base64` — the public key or signature is not valid base64url
    * `:invalid_key` — the public key does not decode to 32 bytes
    * `:invalid_signature` — the signature has the wrong size or does not verify

  Verification is stateless, matching the `sigil-protocol` crate: replay
  protection (tracking seen nonces, enforcing timestamp freshness) is the
  caller's responsibility.
  """
  @spec verify(t(), String.t()) :: :ok | {:error, term()}
  def verify(envelope, public_key_b64u) when is_map(envelope) and is_binary(public_key_b64u) do
    with {:ok, fields} <- fetch_fields(envelope),
         {:ok, verdict} <- parse_verdict(fields.verdict),
         {:ok, public_key} <- decode_public_key(public_key_b64u),
         {:ok, signature} <- decode_signature(fields.signature) do
      bytes = canonical_bytes(fields.identity, verdict, fields.timestamp, fields.nonce)

      # :crypto.verify/5 uses OpenSSL's constant-time comparison internally,
      # so this is safe against timing attacks on signature verification.
      # A 32-byte key that is not a valid curve point makes it raise;
      # that is a failed verification, same as the NIF backend reports.
      try do
        if :crypto.verify(:eddsa, :none, bytes, signature, [public_key, :ed25519]) do
          :ok
        else
          {:error, :invalid_signature}
        end
      rescue
        ErlangError -> {:error, :invalid_signature}
      end
    end
  end

  def verify(_, _), do: {:error, :invalid_envelope}

  @doc "Generate an ISO 8601 timestamp with millisecond precision."
  @spec generate_timestamp() :: String.t()
  def generate_timestamp do
    DateTime.utc_now(:millisecond)
    |> DateTime.to_iso8601()
  end

  @doc "Generate a 16-byte cryptographically random nonce as hex."
  @spec generate_nonce() :: String.t()
  def generate_nonce do
    :crypto.strong_rand_bytes(16)
    |> Base.encode16(case: :lower)
  end

  defp format_verdict(:allowed), do: "Allowed"
  defp format_verdict(:blocked), do: "Blocked"
  defp format_verdict(:scanned), do: "Scanned"

  # Canonical bytes use lowercase to match sigil-protocol crate
  defp canonical_verdict(:allowed), do: "allowed"
  defp canonical_verdict(:blocked), do: "blocked"
  defp canonical_verdict(:scanned), do: "scanned"

  defp parse_verdict("Allowed"), do: {:ok, :allowed}
  defp parse_verdict("Blocked"), do: {:ok, :blocked}
  defp parse_verdict("Scanned"), do: {:ok, :scanned}
  defp parse_verdict(_), do: {:error, :invalid_verdict}

  # Map.get/2 instead of envelope["..."]: structs satisfy is_map/1 but
  # do not implement Access, and verify/2 must never raise.
  defp fetch_fields(envelope) do
    fields = %{
      identity: Map.get(envelope, "identity"),
      verdict: Map.get(envelope, "verdict"),
      timestamp: Map.get(envelope, "timestamp"),
      nonce: Map.get(envelope, "nonce"),
      signature: Map.get(envelope, "signature")
    }

    if Enum.all?(Map.values(fields), &is_binary/1) do
      {:ok, fields}
    else
      {:error, :missing_field}
    end
  end

  defp decode_public_key(public_key_b64u) do
    case Base.url_decode64(public_key_b64u, padding: false) do
      # Ed25519 public keys are exactly 32 bytes
      {:ok, key} when byte_size(key) == 32 -> {:ok, key}
      {:ok, _} -> {:error, :invalid_key}
      :error -> {:error, :invalid_base64}
    end
  end

  defp decode_signature(signature_b64u) do
    case Base.url_decode64(signature_b64u, padding: false) do
      # Ed25519 signatures are exactly 64 bytes
      {:ok, signature} when byte_size(signature) == 64 -> {:ok, signature}
      {:ok, _} -> {:error, :invalid_signature}
      :error -> {:error, :invalid_base64}
    end
  end
end
