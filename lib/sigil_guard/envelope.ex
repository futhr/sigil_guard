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
      "verdict" => format_verdict(verdict)
    }
    |> then(fn fields ->
      @canonical_keys
      |> Enum.map(fn key -> [?", key, ?", ?:, Jason.encode!(fields[key])] end)
      |> Enum.intersperse(",")
      |> then(fn parts -> [?{ | parts] ++ [?}] end)
      |> IO.iodata_to_binary()
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
  """
  @spec verify(t(), String.t()) :: :ok | {:error, term()}
  def verify(envelope, public_key_b64u) do
    with {:ok, public_key} <- Base.url_decode64(public_key_b64u, padding: false),
         {:ok, signature} <- Base.url_decode64(envelope["signature"], padding: false) do
      identity = envelope["identity"]
      verdict = parse_verdict(envelope["verdict"])
      timestamp = envelope["timestamp"]
      nonce_hex = envelope["nonce"]

      bytes = canonical_bytes(identity, verdict, timestamp, nonce_hex)

      # :crypto.verify/5 uses OpenSSL's constant-time comparison internally,
      # so this is safe against timing attacks on signature verification.
      if :crypto.verify(:eddsa, :none, bytes, signature, [public_key, :ed25519]) do
        :ok
      else
        {:error, :invalid_signature}
      end
    else
      :error -> {:error, :invalid_base64}
    end
  end

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

  defp parse_verdict("Allowed"), do: :allowed
  defp parse_verdict("Blocked"), do: :blocked
  defp parse_verdict("Scanned"), do: :scanned
end
