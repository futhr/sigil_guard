defmodule SigilGuard.Confirmation do
  @moduledoc """
  Approval tokens bound to runtime action digests.

  Runtime gates can return `{:confirm, reason}` when a boundary crossing is
  risky but eligible for explicit approval. This module issues short-lived
  HMAC-signed tokens for those decisions. A token is bound to a deterministic
  digest of the exact payload and boundary context, so it cannot be reused for
  a different tool call, tool result, sink, actor, or trust boundary.

  Tokens are stateless by default. They prevent cross-action replay by binding
  to the action digest and expiry. Pass `consume: true` to `verify/5` or
  `valid?/5` to enforce single-use semantics with `SigilGuard.ReplayStore`.
  """

  alias SigilGuard.Context
  alias SigilGuard.Decision
  alias SigilGuard.ReplayStore

  @version 1
  @token_type "sigil_guard.confirmation.v1"
  @default_ttl_ms 300_000
  @min_key_bytes 16

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
    context_map =
      context
      |> Context.new()
      |> Map.from_struct()

    %{
      "context" => context_map,
      "payload" => payload
    }
    |> canonical_bytes()
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end

  @doc """
  Issue a short-lived confirmation token for a confirmable decision.

  Options:

    * `:actor` - approving actor identifier. Defaults to context actor or identity.
    * `:ttl_ms` - token lifetime in milliseconds. Defaults to 5 minutes.
    * `:now` - `DateTime` used for deterministic tests.
    * `:nonce` - nonce used for deterministic tests.
  """
  @spec issue(term(), Context.t() | map() | keyword(), Decision.t(), binary(), keyword()) ::
          {:ok, String.t()} | {:error, term()}
  def issue(payload, context, %Decision{} = decision, key, opts \\ []) do
    context = Context.new(context)

    with :ok <- validate_key(key),
         :ok <- validate_confirmable(decision) do
      now = Keyword.get_lazy(opts, :now, fn -> DateTime.utc_now(:millisecond) end)
      ttl_ms = Keyword.get(opts, :ttl_ms, @default_ttl_ms)

      claims =
        build_claims(payload, context, decision, %{
          actor: actor(context, opts),
          issued_at: DateTime.to_iso8601(now),
          expires_at: expires_at(now, ttl_ms),
          nonce: Keyword.get_lazy(opts, :nonce, &generate_nonce/0)
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
         :ok <- validate_digest(claims, payload, context),
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

  defp build_claims(payload, context, decision, attrs) do
    %{
      "v" => @version,
      "typ" => @token_type,
      "alg" => "HS256",
      "actor" => attrs.actor,
      "action_digest" => action_digest(payload, context),
      "decision" => "confirm",
      "action" => Atom.to_string(decision.action),
      "reason" => decision.reason || "",
      "issued_at" => attrs.issued_at,
      "expires_at" => attrs.expires_at,
      "nonce" => attrs.nonce
    }
  end

  defp encode_token(claims, key) do
    body = Jason.encode!(claims)
    signature = sign_claims(claims, key)

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
    expected = sign_claims(claims, key)

    if secure_compare(expected, signature) do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  defp sign_claims(claims, key) do
    :crypto.mac(:hmac, :sha256, key, canonical_bytes(claims))
  end

  defp validate_claims(%{
         "v" => @version,
         "typ" => @token_type,
         "alg" => "HS256",
         "actor" => actor,
         "action_digest" => digest,
         "decision" => "confirm",
         "action" => action,
         "issued_at" => issued_at,
         "expires_at" => expires_at,
         "nonce" => nonce
       })
       when is_binary(actor) and is_binary(digest) and is_binary(action) and
              is_binary(issued_at) and is_binary(expires_at) and is_binary(nonce) do
    :ok
  end

  defp validate_claims(_), do: {:error, :invalid_token}

  defp validate_expiry(%{"expires_at" => expires_at}, opts) do
    now = Keyword.get_lazy(opts, :now, fn -> DateTime.utc_now(:millisecond) end)

    case DateTime.from_iso8601(expires_at) do
      {:ok, expires_at_dt, _} ->
        if DateTime.compare(now, expires_at_dt) == :gt, do: {:error, :expired}, else: :ok

      _ ->
        {:error, :invalid_token}
    end
  end

  defp validate_digest(%{"action_digest" => digest}, payload, context) do
    expected = action_digest(payload, context)

    if secure_compare(expected, digest), do: :ok, else: {:error, :digest_mismatch}
  end

  defp maybe_consume_nonce(claims, opts) do
    if Keyword.get(opts, :consume, false) do
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
    now = Keyword.get_lazy(opts, :now, fn -> DateTime.utc_now(:millisecond) end)

    case DateTime.from_iso8601(expires_at) do
      {:ok, expires_at_dt, _} ->
        {:ok, max(DateTime.diff(expires_at_dt, now, :millisecond), 1)}

      _ ->
        {:error, :invalid_token}
    end
  end

  defp validate_key(key) when is_binary(key) and byte_size(key) >= @min_key_bytes, do: :ok
  defp validate_key(_), do: {:error, :invalid_key}

  defp validate_confirmable(decision) do
    if Decision.confirm?(decision), do: :ok, else: {:error, :not_confirmable}
  end

  defp actor(%Context{actor: actor}, _) when is_binary(actor), do: actor
  defp actor(%Context{identity: identity}, _) when is_binary(identity), do: identity
  defp actor(_, opts), do: Keyword.get(opts, :actor, "unknown")

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
