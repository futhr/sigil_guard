defmodule SigilGuard.Envelope do
  @moduledoc """
  SIGIL envelope implementation for MCP JSON-RPC `_sigil` metadata.

  Implements SigilGuard's existing envelope contract:
  - Canonical bytes: lexicographic key order, compact JSON, no whitespace,
    excluding `signature` and `reason`
  - Ed25519 signature, base64url-encoded (no padding)
  - ISO 8601 timestamp with millisecond precision (UTC)
  - 16-byte cryptographically random nonce, hex-encoded
  - Explicit compatibility profiles for lowercase and legacy title-cased
    wire verdicts

  ## Signing

  Signing requires a module implementing `SigilGuard.Signer`:

      envelope = SigilGuard.Envelope.sign("did:example:agent", :allowed, signer: MySigner)

  New envelopes emit lowercase verdicts by default. Use
  `profile: :legacy_sigil_guard` or
  `wire_verdict_format: :legacy_titlecase` only when an existing
  integration requires title-cased verdicts.

  ## Verification

      :ok = SigilGuard.Envelope.verify(envelope, public_key_b64u)

  Verification accepts legacy title-cased verdicts in transition profiles
  and can enforce timestamp skew plus nonce replay checks:

      :ok = SigilGuard.Envelope.verify(envelope, public_key_b64u,
        max_skew_ms: 300_000,
        replay: true
      )

  """

  alias SigilGuard.Config
  alias SigilGuard.Profile
  alias SigilGuard.ReplayStore

  @type verdict :: :allowed | :blocked | :scanned
  @type profile :: Profile.t()

  @type t :: %{
          required(String.t()) => String.t()
        }

  @canonical_keys ~w(identity nonce timestamp verdict)
  @valid_verdicts [:allowed, :blocked, :scanned]

  @doc """
  Produce the canonical byte representation for signing.

  Fields are serialized as compact JSON with lexicographic key order,
  no whitespace, excluding `signature` and `reason`. This matches the
  SIGIL reference canonical byte format.
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
    * `:profile` — protocol profile (default: configured `:protocol_profile`)
    * `:wire_verdict_format` — `:lowercase` or `:legacy_titlecase`

  A `:blocked` verdict must include `:reason`.

  Returns a map suitable for embedding as the `_sigil` field in MCP JSON-RPC params.
  """
  @spec sign(String.t(), verdict(), keyword()) :: t()
  def sign(identity, verdict, opts) do
    signer = Keyword.fetch!(opts, :signer)
    reason = Keyword.get(opts, :reason)
    timestamp = Keyword.get_lazy(opts, :timestamp, &generate_timestamp/0)
    nonce_hex = Keyword.get_lazy(opts, :nonce, &generate_nonce/0)
    profile = profile_from_opts(opts)

    wire_verdict_format =
      Keyword.get(opts, :wire_verdict_format, Profile.wire_verdict_format(profile))

    validate_sign_args!(identity, verdict, reason, wire_verdict_format)

    bytes = canonical_bytes(identity, verdict, timestamp, nonce_hex)
    signature = signer.sign(bytes)
    signature_b64u = Base.url_encode64(signature, padding: false)

    envelope = %{
      "identity" => identity,
      "verdict" => format_verdict(verdict, wire_verdict_format),
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
    * `:invalid_verdict` — verdict is not accepted by the active profile
    * `:blocked_reason_required` — a strict profile saw blocked without reason
    * `:invalid_timestamp` — timestamp cannot be parsed when skew checking is enabled
    * `:stale_envelope` — timestamp is outside the configured skew window
    * `:replay_detected` — replay protection saw the identity/nonce pair already
    * `:invalid_base64` — the public key or signature is not valid base64url
    * `:invalid_key` — the public key does not decode to 32 bytes
    * `:invalid_signature` — the signature has the wrong size or does not verify

  ## Options

    * `:profile` — protocol profile (default: configured `:protocol_profile`)
    * `:max_skew_ms` — when set, require timestamp freshness within this window
    * `:replay` — set `true` to store and reject duplicate identity/nonce pairs
    * `:replay_ttl_ms` — TTL for replay entries (defaults to `:max_skew_ms` or 5 min)
    * `:blocked_reason` — `:allow` or `:require`; defaults by profile
  """
  @spec verify(t(), String.t(), keyword()) :: :ok | {:error, term()}
  def verify(envelope, public_key_b64u, opts \\ [])

  def verify(envelope, public_key_b64u, opts)
      when is_map(envelope) and is_binary(public_key_b64u) and is_list(opts) do
    profile = profile_from_opts(opts)

    with {:ok, fields} <- fetch_fields(envelope),
         {:ok, verdict} <- parse_verdict(fields.verdict, profile),
         :ok <- validate_blocked_reason(verdict, Map.get(envelope, "reason"), profile, opts),
         {:ok, public_key} <- decode_public_key(public_key_b64u),
         {:ok, signature} <- decode_signature(fields.signature),
         :ok <- verify_signature(fields, verdict, public_key, signature),
         :ok <- validate_freshness(fields.timestamp, opts) do
      validate_replay(fields.identity, fields.nonce, opts)
    end
  end

  def verify(_, _, _), do: {:error, :invalid_envelope}

  defp verify_signature(fields, verdict, public_key, signature) do
    bytes = canonical_bytes(fields.identity, verdict, fields.timestamp, fields.nonce)

    # :crypto.verify/5 uses OpenSSL's constant-time comparison internally,
    # so this is safe against timing attacks on signature verification.
    # A 32-byte key that is not a valid curve point makes it raise;
    # that is a failed verification.
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

  defp validate_sign_args!(identity, verdict, reason, wire_verdict_format) do
    cond do
      not is_binary(identity) ->
        raise ArgumentError, "identity must be a string"

      verdict not in @valid_verdicts ->
        raise ArgumentError, "invalid envelope verdict #{inspect(verdict)}"

      verdict == :blocked and not is_binary(reason) ->
        raise ArgumentError, "blocked envelopes require a reason"

      wire_verdict_format not in [:lowercase, :legacy_titlecase] ->
        raise ArgumentError,
              "invalid wire_verdict_format #{inspect(wire_verdict_format)}; " <>
                "expected :lowercase or :legacy_titlecase"

      true ->
        :ok
    end
  end

  defp format_verdict(verdict, :lowercase), do: canonical_verdict(verdict)
  defp format_verdict(:allowed, :legacy_titlecase), do: "Allowed"
  defp format_verdict(:blocked, :legacy_titlecase), do: "Blocked"
  defp format_verdict(:scanned, :legacy_titlecase), do: "Scanned"

  # Canonical bytes use lowercase to match sigil-protocol crate
  defp canonical_verdict(:allowed), do: "allowed"
  defp canonical_verdict(:blocked), do: "blocked"
  defp canonical_verdict(:scanned), do: "scanned"

  defp parse_verdict(verdict, profile) do
    case {verdict, Profile.verdict_acceptance(profile)} do
      {"allowed", _} -> {:ok, :allowed}
      {"blocked", _} -> {:ok, :blocked}
      {"scanned", _} -> {:ok, :scanned}
      {"Allowed", :legacy_and_lowercase} -> {:ok, :allowed}
      {"Blocked", :legacy_and_lowercase} -> {:ok, :blocked}
      {"Scanned", :legacy_and_lowercase} -> {:ok, :scanned}
      _ -> {:error, :invalid_verdict}
    end
  end

  defp validate_blocked_reason(:blocked, reason, profile, opts) do
    policy =
      Keyword.get_lazy(opts, :blocked_reason, fn ->
        if Profile.require_blocked_reason_on_verify?(profile), do: :require, else: :allow
      end)

    case {policy, reason} do
      {:require, reason} when not is_binary(reason) or reason == "" ->
        {:error, :blocked_reason_required}

      _ ->
        :ok
    end
  end

  defp validate_blocked_reason(_, _, _, _), do: :ok

  defp validate_freshness(timestamp, opts) do
    case Keyword.get(opts, :max_skew_ms) do
      nil ->
        :ok

      max_skew_ms when is_integer(max_skew_ms) and max_skew_ms >= 0 ->
        validate_timestamp_skew(timestamp, max_skew_ms)

      _ ->
        {:error, :invalid_timestamp}
    end
  end

  defp validate_timestamp_skew(timestamp, max_skew_ms) do
    case DateTime.from_iso8601(timestamp) do
      {:ok, parsed, _} ->
        if timestamp_within_skew?(parsed, max_skew_ms), do: :ok, else: {:error, :stale_envelope}

      {:error, _} ->
        {:error, :invalid_timestamp}
    end
  end

  defp timestamp_within_skew?(parsed, max_skew_ms) do
    skew_ms =
      DateTime.utc_now()
      |> DateTime.diff(parsed, :millisecond)
      |> abs()

    skew_ms <= max_skew_ms
  end

  defp validate_replay(identity, nonce, opts) do
    if Keyword.get(opts, :replay, false) do
      ttl_ms = Keyword.get(opts, :replay_ttl_ms, Keyword.get(opts, :max_skew_ms, 300_000))
      ReplayStore.check_and_put(identity, nonce, ttl_ms)
    else
      :ok
    end
  end

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

  defp profile_from_opts(opts) do
    opts
    |> Keyword.get_lazy(:profile, &Config.protocol_profile/0)
    |> Profile.normalize!()
  end
end
