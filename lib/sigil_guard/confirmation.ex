defmodule SigilGuard.Confirmation do
  @moduledoc """
  Approval tokens bound to runtime action digests.

  Runtime gates can return `{:confirm, reason}` when a boundary crossing is
  risky but eligible for explicit approval. This module issues short-lived
  HMAC-signed tokens for those decisions. A token is bound to a deterministic
  digest of the exact payload and boundary context, so it cannot be reused for
  a different tool call, tool result, sink, actor, or trust boundary.

  Tokens are stateless by default. They prevent cross-action replay by binding
  to the action digest, manifest digest when present, and expiry. Pass
  `consume: true` to `verify/5` or `valid?/5` to enforce single-use semantics
  with `SigilGuard.ReplayStore`.
  """

  alias SigilGuard.Attestation.Digest
  alias SigilGuard.Context
  alias SigilGuard.Decision
  alias SigilGuard.ReplayStore

  @version 2
  @token_type "sigil_guard.confirmation.v2"
  @default_ttl_ms 300_000
  @min_key_bytes 16
  @sha256_regex ~r/^[0-9a-f]{64}$/
  @nonce_regex ~r/^[0-9a-f]{32}$/

  @type claims :: %{
          required(String.t()) => String.t() | integer()
        }

  @doc """
  Compute the deterministic digest for a payload crossing a boundary.

  The digest is a lowercase SHA-256 hex string over canonical bytes containing
  the payload and normalized `SigilGuard.Context`.
  """
  @spec action_digest(term(), Context.t() | map() | keyword()) :: String.t()
  def action_digest(payload, context) do
    case fetch_action_digest(payload, context) do
      {:ok, digest} -> digest
      {:error, reason} -> raise ArgumentError, "could not compute action digest: #{reason}"
    end
  end

  @doc """
  Safely compute the deterministic action digest.

  Returns `{:error, :invalid_payload}` when the payload or context cannot be
  represented as canonical JSON for action binding.
  """
  @spec fetch_action_digest(term(), Context.t() | map() | keyword()) ::
          {:ok, String.t()} | {:error, :invalid_payload}
  def fetch_action_digest(payload, context) do
    context_map =
      context
      |> Context.new()
      |> Map.from_struct()

    digest =
      %{
        "context" => context_map,
        "payload" => payload
      }
      |> canonical_bytes()
      |> then(&:crypto.hash(:sha256, &1))
      |> Base.encode16(case: :lower)

    {:ok, digest}
  rescue
    _ in [ArgumentError, Jason.EncodeError, Protocol.UndefinedError] ->
      {:error, :invalid_payload}
  end

  @doc """
  Issue a short-lived confirmation token for a confirmable decision.

  Options:

    * `:actor` - approving actor identifier. Defaults to context actor or identity.
    * `:ttl_ms` - token lifetime in milliseconds. Defaults to 5 minutes.
    * `:now` - `DateTime` used for deterministic tests.
    * `:nonce` - nonce used for deterministic tests.
    * `:manifest` - pinned manifest digest to bind into the token.
  """
  @spec issue(term(), Context.t() | map() | keyword(), Decision.t(), binary(), keyword()) ::
          {:ok, String.t()} | {:error, term()}
  def issue(payload, context, %Decision{} = decision, key, opts \\ []) do
    context = Context.new(context)

    with :ok <- validate_key(key),
         :ok <- validate_confirmable(decision),
         {:ok, now} <- issue_now(opts),
         {:ok, ttl_ms} <- issue_ttl_ms(opts),
         {:ok, actor} <- issue_actor(context, opts),
         {:ok, nonce} <- issue_nonce(opts),
         {:ok, manifest_digest} <- issue_manifest_digest(opts),
         {:ok, digests} <- confirmation_digests(payload, context) do
      claims =
        build_claims(decision, %{
          actor: actor,
          action_digest: digests.action_digest,
          payload_digest: digests.payload_digest,
          context_digest: digests.context_digest,
          manifest_digest: manifest_digest,
          issued_at: DateTime.to_iso8601(now),
          expires_at: expires_at(now, ttl_ms),
          nonce: nonce
        })

      {:ok, encode_token(claims, key)}
    end
  end

  @doc """
  Verify a confirmation token against the expected payload and context.

  Returns `{:ok, claims}` for a valid token or `{:error, reason}`.

  Pass `consume: true` to record the token nonce in `SigilGuard.ReplayStore`
  until the token expires and reject a second verification with
  `{:error, :replay_detected}`.
  """
  @spec verify(String.t(), term(), Context.t() | map() | keyword(), binary(), keyword()) ::
          {:ok, claims()} | {:error, term()}
  def verify(token, payload, context, key, opts \\ [])

  def verify(token, payload, context, key, opts) when is_binary(token) do
    with :ok <- validate_key(key),
         {:ok, claims, signature} <- decode_token(token),
         :ok <- verify_signature(claims, signature, key),
         :ok <- validate_claims(claims),
         :ok <- validate_expiry(claims, opts),
         :ok <- validate_digest(claims, payload, context, opts),
         :ok <- maybe_consume_nonce(claims, opts) do
      {:ok, claims}
    end
  end

  def verify(_, _, _, _, _), do: {:error, :invalid_token}

  @doc """
  Return true when `token` verifies for the given payload and context.

  When `consume: true` is passed, a successful call consumes the token nonce in
  the same way as `verify/5`.
  """
  @spec valid?(String.t(), term(), Context.t() | map() | keyword(), binary(), keyword()) ::
          boolean()
  def valid?(token, payload, context, key, opts \\ []) do
    match?({:ok, _}, verify(token, payload, context, key, opts))
  end

  defp build_claims(decision, attrs) do
    claims = %{
      "v" => @version,
      "typ" => @token_type,
      "alg" => "HS256",
      "actor" => attrs.actor,
      "action_digest" => attrs.action_digest,
      "payload_digest" => attrs.payload_digest,
      "context_digest" => attrs.context_digest,
      "decision" => "confirm",
      "action" => Atom.to_string(decision.action),
      "reason" => decision.reason || "",
      "issued_at" => attrs.issued_at,
      "expires_at" => attrs.expires_at,
      "nonce" => attrs.nonce
    }

    maybe_put_manifest_digest(claims, attrs.manifest_digest)
  end

  defp maybe_put_manifest_digest(claims, nil), do: claims
  defp maybe_put_manifest_digest(claims, digest), do: Map.put(claims, "manifest_digest", digest)

  defp encode_token(claims, key) do
    body = canonical_bytes(claims)
    signature = sign_bytes(body, key)

    [
      Base.url_encode64(body, padding: false),
      ".",
      Base.url_encode64(signature, padding: false)
    ]
    |> IO.iodata_to_binary()
  end

  defp decode_token(token) do
    case String.split(token, ".", parts: 2) do
      [body_b64u, signature_b64u] ->
        with {:ok, body} <- decode_b64u(body_b64u),
             {:ok, claims} <- Jason.decode(body),
             :ok <- validate_canonical_body(body, claims),
             {:ok, signature} <- decode_b64u(signature_b64u) do
          {:ok, claims, signature}
        else
          _ -> {:error, :invalid_token}
        end

      _ ->
        {:error, :invalid_token}
    end
  end

  defp decode_b64u(value), do: Base.url_decode64(value, padding: false)

  defp verify_signature(claims, signature, key) do
    expected =
      claims
      |> canonical_bytes()
      |> sign_bytes(key)

    if secure_compare(expected, signature) do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  defp validate_canonical_body(body, claims) do
    if secure_compare(body, canonical_bytes(claims)), do: :ok, else: {:error, :invalid_token}
  end

  defp sign_bytes(bytes, key), do: :crypto.mac(:hmac, :sha256, key, bytes)

  defp validate_claims(
         %{
           "v" => @version,
           "typ" => @token_type,
           "alg" => "HS256",
           "decision" => "confirm"
         } = claims
       ) do
    with {:ok, fields} <- claim_fields(claims),
         :ok <- validate_claim_digests(fields) do
      validate_claim_nonce(fields.nonce)
    end
  end

  defp validate_claims(_), do: {:error, :invalid_token}

  defp claim_fields(claims) do
    fields = %{
      actor: Map.get(claims, "actor"),
      action: Map.get(claims, "action"),
      action_digest: Map.get(claims, "action_digest"),
      payload_digest: Map.get(claims, "payload_digest"),
      context_digest: Map.get(claims, "context_digest"),
      issued_at: Map.get(claims, "issued_at"),
      expires_at: Map.get(claims, "expires_at"),
      nonce: Map.get(claims, "nonce")
    }

    if Enum.all?(fields, fn {_, value} -> is_binary(value) end) do
      {:ok, fields}
    else
      {:error, :invalid_token}
    end
  end

  defp validate_claim_digests(fields) do
    if valid_sha256?(fields.action_digest) and valid_sha256?(fields.payload_digest) and
         valid_sha256?(fields.context_digest) do
      :ok
    else
      {:error, :invalid_token}
    end
  end

  defp validate_claim_nonce(nonce) do
    if valid_nonce_claim?(nonce), do: :ok, else: {:error, :invalid_token}
  end

  defp valid_sha256?(value), do: value =~ @sha256_regex
  defp valid_nonce_claim?(nonce), do: nonce =~ @nonce_regex

  defp validate_expiry(%{"expires_at" => expires_at}, opts) do
    with {:ok, now} <- issue_now(opts),
         {:ok, expires_at_dt} <- parse_datetime(expires_at) do
      if DateTime.compare(now, expires_at_dt) == :gt, do: {:error, :expired}, else: :ok
    end
  end

  defp validate_digest(claims, payload, context, opts) do
    with {:ok, expected} <- confirmation_digests(payload, context),
         :ok <- validate_digest_claim(claims, "action_digest", expected.action_digest),
         :ok <- validate_digest_claim(claims, "payload_digest", expected.payload_digest),
         :ok <- validate_digest_claim(claims, "context_digest", expected.context_digest) do
      validate_manifest_digest(claims, opts)
    end
  end

  defp validate_digest_claim(claims, key, expected) do
    case Map.fetch(claims, key) do
      {:ok, ^expected} -> :ok
      {:ok, digest} when is_binary(digest) -> {:error, :digest_mismatch}
      _ -> {:error, :invalid_token}
    end
  end

  defp validate_manifest_digest(%{"manifest_digest" => digest}, opts) when is_binary(digest) do
    case expected_manifest_digest(opts) do
      {:ok, ^digest} -> :ok
      {:ok, _} -> {:error, :manifest_digest_mismatch}
      :none -> {:error, :manifest_digest_mismatch}
      {:error, _} -> {:error, :manifest_digest_mismatch}
    end
  end

  defp validate_manifest_digest(%{}, opts) do
    case expected_manifest_digest(opts) do
      :none -> :ok
      {:ok, _} -> {:error, :manifest_digest_mismatch}
      {:error, _} -> {:error, :manifest_digest_mismatch}
    end
  end

  defp maybe_consume_nonce(claims, opts) do
    if Keyword.get(opts, :consume, true) do
      consume_nonce(claims, opts)
    else
      :ok
    end
  end

  defp consume_nonce(%{"actor" => actor, "nonce" => nonce} = claims, opts) do
    with {:ok, ttl_ms} <- replay_ttl_ms(claims, opts) do
      ReplayStore.check_and_put("confirmation:" <> actor, nonce, ttl_ms)
    end
  end

  defp replay_ttl_ms(%{"expires_at" => expires_at}, opts) do
    with {:ok, now} <- issue_now(opts),
         {:ok, expires_at_dt} <- parse_datetime(expires_at) do
      {:ok, max(DateTime.diff(expires_at_dt, now, :millisecond), 1)}
    end
  end

  defp validate_key(key) when is_binary(key) and byte_size(key) >= @min_key_bytes, do: :ok
  defp validate_key(_), do: {:error, :invalid_key}

  defp validate_confirmable(decision) do
    if Decision.confirm?(decision), do: :ok, else: {:error, :not_confirmable}
  end

  defp issue_now(opts) do
    case Keyword.get_lazy(opts, :now, fn -> DateTime.utc_now(:millisecond) end) do
      %DateTime{} = now -> {:ok, now}
      _ -> {:error, :invalid_now}
    end
  end

  defp issue_ttl_ms(opts) do
    case Keyword.get(opts, :ttl_ms, @default_ttl_ms) do
      ttl_ms when is_integer(ttl_ms) and ttl_ms > 0 -> {:ok, ttl_ms}
      _ -> {:error, :invalid_ttl}
    end
  end

  defp issue_nonce(opts) do
    case Keyword.get_lazy(opts, :nonce, &generate_nonce/0) do
      nonce when is_binary(nonce) ->
        if nonce =~ @nonce_regex, do: {:ok, nonce}, else: {:error, :invalid_nonce}

      _ ->
        {:error, :invalid_nonce}
    end
  end

  defp confirmation_digests(payload, context) do
    context = Context.new(context)
    statement_type = context.phase

    with {:ok, action_digest} <- fetch_action_digest(payload, context),
         {:ok, payload_digest} <- Digest.payload_digest(payload),
         {:ok, context_digest} <- Digest.context_digest(statement_type, context) do
      {:ok,
       %{
         action_digest: action_digest,
         payload_digest: payload_digest,
         context_digest: context_digest
       }}
    else
      {:error, :unsupported_number_range} -> {:error, :invalid_payload}
      {:error, :unknown_statement_type} -> {:error, :invalid_payload}
      {:error, reason} -> {:error, reason}
    end
  end

  defp issue_manifest_digest(opts) do
    case Keyword.get(opts, :manifest) do
      nil -> {:ok, nil}
      digest when is_binary(digest) -> validate_manifest_digest_value(digest)
      _ -> {:error, :invalid_payload}
    end
  end

  defp expected_manifest_digest(opts) do
    case Keyword.get(opts, :manifest) do
      nil -> :none
      digest when is_binary(digest) -> validate_manifest_digest_value(digest)
      _ -> {:error, :invalid_payload}
    end
  end

  defp validate_manifest_digest_value(digest) do
    if digest =~ @sha256_regex do
      {:ok, digest}
    else
      {:error, :invalid_payload}
    end
  end

  defp issue_actor(%Context{actor: actor}, _) when is_binary(actor) and actor != "",
    do: {:ok, actor}

  defp issue_actor(%Context{identity: identity}, _) when is_binary(identity) and identity != "",
    do: {:ok, identity}

  defp issue_actor(_, opts) do
    case Keyword.get(opts, :actor, "unknown") do
      actor when is_binary(actor) and actor != "" -> {:ok, actor}
      _ -> {:error, :invalid_actor}
    end
  end

  defp parse_datetime(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _} -> {:ok, datetime}
      _ -> {:error, :invalid_token}
    end
  end

  defp expires_at(now, ttl_ms) do
    now
    |> DateTime.add(ttl_ms, :millisecond)
    |> DateTime.to_iso8601()
  end

  defp generate_nonce do
    16
    |> :crypto.strong_rand_bytes()
    |> Base.encode16(case: :lower)
  end

  defp canonical_bytes(value) do
    value
    |> canonical_iodata()
    |> IO.iodata_to_binary()
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
    value
    |> Enum.map(&canonical_iodata/1)
    |> Enum.intersperse(",")
    |> then(&[?[, &1, ?]])
  end

  defp canonical_iodata(value)
       when is_atom(value) and not is_boolean(value) and not is_nil(value) do
    value
    |> Atom.to_string()
    |> Jason.encode!()
  end

  defp canonical_iodata(value) do
    Jason.encode!(value)
  end

  defp canonical_key(key) when is_atom(key), do: Atom.to_string(key)
  defp canonical_key(key) when is_binary(key), do: key
  defp canonical_key(key), do: to_string(key)

  defp secure_compare(a, b) when byte_size(a) == byte_size(b) do
    secure_compare(a, b, 0)
  end

  defp secure_compare(_, _), do: false

  defp secure_compare(<<a, rest_a::binary>>, <<b, rest_b::binary>>, diff) do
    secure_compare(rest_a, rest_b, Bitwise.bor(diff, Bitwise.bxor(a, b)))
  end

  defp secure_compare(<<>>, <<>>, diff), do: diff == 0
end
