defmodule SigilGuard.AgentCard do
  @moduledoc """
  Agent cards as DSSE-signed capability-manifest analogs (SP.13).

  An agent card is to an agent what a capability manifest is to a tool: signed
  metadata that steers a counterpart's behavior. It is supply-chain input, never
  trusted context - card `name`/`description` entering model context MUST still
  cross the boundary pipeline like any untrusted content.

  A card is a closed-schema map. `new/1` validates and normalizes it, `digest/1`
  computes the lowercase-hex SHA-256 over its compact JCS bytes, `sign/2,3` wraps
  the card in a DSSE envelope, and `verify/2,3` resolves the issuer against
  bundle-declared card signers, enforces JCS byte-equality, and checks freshness.

  Trust flows from the bundle: bundle-declared issuers (the `"agent_card"`
  delegate role, SP.02) sign cards, cards list the agent's own keys, and those
  agent keys sign the agent's attestations. Agent keys never appear in the
  bundle. Card trust comes from the bundle, never from the transport that
  delivered the card.

  ## Example

      iex> {pub, _priv} = :crypto.generate_key(:eddsa, :ed25519, :binary.copy(<<0x41>>, 32))
      ...>
      ...> card = %{
      ...>   "kind" => "sigil_guard_agent_card",
      ...>   "schema_version" => "1",
      ...>   "agent_id" => "spiffe://example.org/agents/peer",
      ...>   "name" => "peer",
      ...>   "version" => "1.0.0",
      ...>   "provider" => "spiffe://example.org/operators/team",
      ...>   "endpoints" => ["https://example.org/peer/a2a"],
      ...>   "capabilities" => [%{"name" => "summarize"}],
      ...>   "protocols" => ["a2a/1.0"],
      ...>   "public_keys" => [
      ...>     %{
      ...>       "algorithm" => "ed25519",
      ...>       "keyid" => SigilGuard.Attestation.Envelope.keyid(pub),
      ...>       "public_key" => Base.url_encode64(pub, padding: false)
      ...>     }
      ...>   ],
      ...>   "trust_zone" => "semi_trusted",
      ...>   "issued_at" => "2026-07-02T12:00:00.000Z",
      ...>   "expires_at" => "2026-08-01T12:00:00.000Z"
      ...> }
      ...>
      ...> {:ok, normalized} = SigilGuard.AgentCard.new(card)
      ...> match?({:ok, _digest}, SigilGuard.AgentCard.digest(normalized))
      true
  """

  alias SigilGuard.Attestation.Digest
  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.Telemetry
  alias SigilGuard.TrustBundle

  @kind "sigil_guard_agent_card"
  @schema_version "1"
  @timestamp_regex ~r/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
  @public_key_algorithm "ed25519"
  @ed25519_public_key_bytes 32
  @default_max_skew_ms 60_000
  @card_issuer_role "agent_card"

  @trust_zones ~w(trusted semi_trusted untrusted)
  @required_fields ~w(
    agent_id
    capabilities
    endpoints
    expires_at
    issued_at
    kind
    name
    protocols
    provider
    public_keys
    schema_version
    trust_zone
    version
  )
  @optional_fields ~w(description scopes)
  @allowed_fields MapSet.new(@required_fields ++ @optional_fields)
  @capability_keys MapSet.new(~w(description name))
  @public_key_keys ~w(algorithm keyid public_key)

  @typedoc "A validated, normalized agent card as a string-keyed map."
  @type card :: %{required(String.t()) => term()}

  @typedoc "Card-issuer trust material: a keyid map or a verified trust bundle."
  @type trust_material ::
          %{optional(String.t()) => binary()} | SigilGuard.TrustBundle.t()

  @type card_error :: :invalid_agent_card | :unsupported_number_range

  @type verify_error ::
          :invalid_envelope
          | :invalid_payload_type
          | :invalid_base64
          | :duplicate_keyid
          | :missing_trust_bundle
          | :unknown_key_id
          | :untrusted_issuer
          | :invalid_signature
          | :invalid_agent_card
          | :card_expired

  @doc """
  Validate and normalize a carried agent card.

  Returns the card as a normalized string-keyed map. Unknown top-level keys,
  missing required fields, retyped fields, unsorted or duplicate list entries, a
  keyid that is not the SHA-256 derivation of its raw key, or
  `expires_at <= issued_at` all fail `:invalid_agent_card`.
  """
  @spec new(map()) :: {:ok, card()} | {:error, card_error()}
  def new(card) when is_map(card) do
    with {:ok, card} <- normalize_card(card),
         :ok <- closed_fields(card),
         :ok <- required_fields(card),
         :ok <- validate_scalars(card),
         :ok <- validate_endpoints(card),
         :ok <- validate_capabilities(card),
         :ok <- validate_protocols(card),
         :ok <- validate_public_keys(card),
         :ok <- validate_scopes(card),
         :ok <- validate_validity_window(card) do
      {:ok, card}
    end
  end

  def new(_), do: {:error, :invalid_agent_card}

  @doc """
  Compute the SP.13 card digest.

  Lowercase-hex SHA-256 over the compact JCS bytes of the normalized card.
  """
  @spec digest(card() | map()) :: {:ok, String.t()} | {:error, card_error()}
  def digest(card) when is_map(card) do
    with {:ok, card} <- new(card),
         {:ok, canonical} <- encode_card(card) do
      {:ok, sha256_hex(canonical)}
    end
  end

  def digest(_), do: {:error, :invalid_agent_card}

  @doc """
  Sign an agent card as a DSSE envelope.

  `signer` is a `SigilGuard.Signer` module holding a card-issuer key. The keyid
  defaults to the derived `"sha256:" <> hex` form; override with `:keyid`.
  """
  @spec sign(card() | map(), module(), keyword()) ::
          {:ok, Envelope.envelope()} | {:error, card_error() | :invalid_signer}
  def sign(card, signer, opts \\ [])

  def sign(card, signer, opts) when is_map(card) and is_atom(signer) and is_list(opts) do
    with {:ok, card} <- new(card),
         {:ok, payload} <- encode_card(card) do
      Envelope.sign(payload, signer, keyid: Keyword.get(opts, :keyid))
    end
  end

  def sign(_, _, _), do: {:error, :invalid_agent_card}

  @doc """
  Verify a DSSE-wrapped agent card and return the normalized card.

  `trust_material` is either a `%{keyid => public_key}` map (authorized issuers
  directly) or a verified `%SigilGuard.TrustBundle{}`, whose `"agent_card"`
  delegate role names the trusted card signers. Verification follows the
  normative order: envelope structure, issuer resolution, Ed25519 over PAE,
  schema validation, JCS byte-equality, and freshness (`:now`/`:max_skew_ms`).
  """
  @spec verify(Envelope.envelope() | term(), trust_material(), keyword()) ::
          {:ok, card()} | {:error, verify_error()}
  def verify(envelope, trust_material, opts \\ []) do
    Telemetry.span([:sigil_guard, :agent_trust, :card_verify], %{}, fn ->
      result = do_verify(envelope, trust_material, opts)
      {result, verify_metadata(result)}
    end)
  end

  defp do_verify(envelope, trust_material, opts) when is_list(opts) do
    with {:ok, authorized, resolver} <- resolve_issuers(trust_material),
         {:ok, payload} <- verify_envelope(envelope, authorized, resolver),
         {:ok, card} <- parse_and_validate(payload),
         :ok <- require_canonical(card, payload),
         :ok <- validate_freshness(card, opts) do
      {:ok, card}
    end
  end

  defp do_verify(_, _, _), do: {:error, :invalid_agent_card}

  defp verify_metadata({:ok, _}), do: %{result: :ok, error: nil}
  defp verify_metadata({:error, reason}), do: %{result: :error, error: reason}

  # -- Issuer resolution ------------------------------------------------------

  defp resolve_issuers(%TrustBundle{document: document}) when is_map(document) do
    bundle_keys = bundle_keys(document)
    role_keyids = card_issuer_keyids(document)
    authorized = Map.take(bundle_keys, role_keyids)
    {:ok, authorized, {:bundle, bundle_keys}}
  end

  defp resolve_issuers(trust_material)
       when is_map(trust_material) and map_size(trust_material) > 0 do
    {:ok, trust_material, :map}
  end

  defp resolve_issuers(_), do: {:error, :missing_trust_bundle}

  defp bundle_keys(%{"keys" => keys}) when is_map(keys) do
    Map.new(keys, fn
      {keyid, %{"public_key" => public_key}} when is_binary(public_key) ->
        {keyid, public_key}

      {keyid, _} ->
        {keyid, nil}
    end)
  end

  defp bundle_keys(_), do: %{}

  defp card_issuer_keyids(%{"roles" => %{"delegates" => delegates}}) when is_list(delegates) do
    case Enum.find(delegates, &(is_map(&1) and Map.get(&1, "name") == @card_issuer_role)) do
      %{"keyids" => keyids} when is_list(keyids) -> Enum.filter(keyids, &is_binary/1)
      _ -> []
    end
  end

  defp card_issuer_keyids(_), do: []

  defp verify_envelope(envelope, authorized, resolver) do
    case Envelope.verify(envelope, drop_nil_values(authorized)) do
      {:ok, payload} -> {:ok, payload}
      {:error, :unknown_key_id} -> classify_unresolved(envelope, resolver)
      {:error, reason} -> {:error, reason}
    end
  end

  defp classify_unresolved(_, :map), do: {:error, :unknown_key_id}

  defp classify_unresolved(envelope, {:bundle, bundle_keys}) do
    if Enum.any?(signature_keyids(envelope), &Map.has_key?(bundle_keys, &1)) do
      {:error, :untrusted_issuer}
    else
      {:error, :unknown_key_id}
    end
  end

  defp signature_keyids(%{} = envelope) do
    case Map.get(envelope, "signatures") || Map.get(envelope, :signatures) do
      signatures when is_list(signatures) ->
        Enum.flat_map(signatures, fn
          %{} = signature -> List.wrap(Map.get(signature, "keyid") || Map.get(signature, :keyid))
          _ -> []
        end)

      _ ->
        []
    end
  end

  defp signature_keyids(_), do: []

  defp drop_nil_values(map) do
    Map.reject(map, fn {_, value} -> is_nil(value) end)
  end

  # -- Payload parsing and canonicalization -----------------------------------

  defp parse_and_validate(payload) do
    case Jason.decode(payload) do
      {:ok, decoded} -> new(decoded)
      {:error, _} -> {:error, :invalid_agent_card}
    end
  end

  defp require_canonical(card, payload) do
    case encode_card(card) do
      {:ok, ^payload} -> :ok
      {:ok, _} -> {:error, :invalid_agent_card}
      {:error, _} -> {:error, :invalid_agent_card}
    end
  end

  defp validate_freshness(card, opts) do
    with {:ok, now} <- freshness_now(opts),
         {:ok, max_skew_ms} <- freshness_skew(opts),
         {:ok, issued_at} <- parse_timestamp(Map.fetch!(card, "issued_at")),
         {:ok, expires_at} <- parse_timestamp(Map.fetch!(card, "expires_at")) do
      skew = max_skew_ms
      not_yet_valid? = DateTime.diff(issued_at, now, :millisecond) > skew
      expired? = DateTime.diff(now, expires_at, :millisecond) > skew

      if not_yet_valid? or expired?, do: {:error, :card_expired}, else: :ok
    end
  end

  defp freshness_now(opts) do
    case Keyword.get(opts, :now) do
      nil -> {:ok, DateTime.utc_now()}
      %DateTime{} = now -> {:ok, now}
      _ -> {:error, :invalid_agent_card}
    end
  end

  defp freshness_skew(opts) do
    case Keyword.get(opts, :max_skew_ms, @default_max_skew_ms) do
      skew when is_integer(skew) and skew >= 0 -> {:ok, skew}
      _ -> {:error, :invalid_agent_card}
    end
  end

  # -- Schema validation ------------------------------------------------------

  defp normalize_card(card) do
    case Digest.normalize(card) do
      {:ok, normalized} when is_map(normalized) -> {:ok, normalized}
      {:ok, _} -> {:error, :invalid_agent_card}
      {:error, _} -> {:error, :invalid_agent_card}
    end
  end

  defp closed_fields(card) do
    if Enum.all?(Map.keys(card), &MapSet.member?(@allowed_fields, &1)) do
      :ok
    else
      {:error, :invalid_agent_card}
    end
  end

  defp required_fields(card) do
    if Enum.all?(@required_fields, &Map.has_key?(card, &1)) do
      :ok
    else
      {:error, :invalid_agent_card}
    end
  end

  defp validate_scalars(card) do
    checks = [
      exact_field(card, "kind", @kind),
      exact_field(card, "schema_version", @schema_version),
      string_field(card, "agent_id"),
      string_field(card, "name"),
      string_field(card, "provider"),
      string_field(card, "version"),
      enum_field(card, "trust_zone", @trust_zones),
      regex_field(card, "issued_at", @timestamp_regex),
      regex_field(card, "expires_at", @timestamp_regex),
      optional_string_field(card, "description")
    ]

    all_ok(checks)
  end

  defp validate_endpoints(card) do
    case Map.fetch(card, "endpoints") do
      {:ok, endpoints} when is_list(endpoints) ->
        if sorted_unique?(endpoints) and Enum.all?(endpoints, &absolute_uri?/1) do
          :ok
        else
          {:error, :invalid_agent_card}
        end

      _ ->
        {:error, :invalid_agent_card}
    end
  end

  defp validate_capabilities(card) do
    with {:ok, capabilities} <- fetch_non_empty_list(card, "capabilities"),
         :ok <- each_ok(capabilities, &valid_capability?/1),
         names <- Enum.map(capabilities, &Map.fetch!(&1, "name")),
         true <- sorted_unique?(names) do
      :ok
    else
      _ -> {:error, :invalid_agent_card}
    end
  end

  defp valid_capability?(entry) when is_map(entry) do
    keys = MapSet.new(Map.keys(entry))

    MapSet.subset?(keys, @capability_keys) and
      non_empty_string?(Map.get(entry, "name")) and
      optional_non_empty_string?(entry, "description")
  end

  defp valid_capability?(_), do: false

  defp validate_protocols(card) do
    with {:ok, protocols} <- fetch_non_empty_list(card, "protocols"),
         true <- Enum.all?(protocols, &non_empty_string?/1),
         true <- sorted_unique?(protocols) do
      :ok
    else
      _ -> {:error, :invalid_agent_card}
    end
  end

  defp validate_public_keys(card) do
    with {:ok, public_keys} <- fetch_non_empty_list(card, "public_keys"),
         :ok <- each_ok(public_keys, &valid_public_key?/1),
         keyids <- Enum.map(public_keys, &Map.fetch!(&1, "keyid")),
         true <- sorted_unique?(keyids) do
      :ok
    else
      _ -> {:error, :invalid_agent_card}
    end
  end

  defp valid_public_key?(entry) when is_map(entry) do
    with true <- Enum.sort(Map.keys(entry)) == @public_key_keys,
         @public_key_algorithm <- Map.fetch!(entry, "algorithm"),
         keyid when is_binary(keyid) <- Map.fetch!(entry, "keyid"),
         encoded when is_binary(encoded) <- Map.fetch!(entry, "public_key"),
         {:ok, raw} <- decode_public_key(encoded),
         true <- Envelope.keyid(raw) == keyid do
      true
    else
      _ -> false
    end
  end

  defp valid_public_key?(_), do: false

  defp decode_public_key(encoded) do
    case Base.url_decode64(encoded, padding: false) do
      {:ok, raw} when byte_size(raw) == @ed25519_public_key_bytes -> {:ok, raw}
      _ -> :error
    end
  end

  defp validate_scopes(card) do
    case Map.fetch(card, "scopes") do
      :error ->
        :ok

      {:ok, scopes} when is_list(scopes) ->
        if Enum.all?(scopes, &non_empty_string?/1) and sorted_unique?(scopes) do
          :ok
        else
          {:error, :invalid_agent_card}
        end

      {:ok, _} ->
        {:error, :invalid_agent_card}
    end
  end

  defp validate_validity_window(card) do
    with {:ok, issued_at} <- parse_timestamp(Map.fetch!(card, "issued_at")),
         {:ok, expires_at} <- parse_timestamp(Map.fetch!(card, "expires_at")),
         :gt <- DateTime.compare(expires_at, issued_at) do
      :ok
    else
      _ -> {:error, :invalid_agent_card}
    end
  end

  # -- Leaf helpers -----------------------------------------------------------

  defp encode_card(card) do
    case JCS.encode(card) do
      {:ok, canonical} -> {:ok, canonical}
      {:error, :unsupported_number_range} -> {:error, :unsupported_number_range}
      {:error, _} -> {:error, :invalid_agent_card}
    end
  end

  defp fetch_non_empty_list(card, field) do
    case Map.fetch(card, field) do
      {:ok, list} when is_list(list) and list != [] -> {:ok, list}
      _ -> :error
    end
  end

  defp each_ok(list, predicate) do
    if Enum.all?(list, predicate), do: :ok, else: :error
  end

  defp sorted_unique?(list) when is_list(list) do
    Enum.all?(list, &is_binary/1) and list == Enum.sort(list) and list == Enum.uniq(list)
  end

  defp sorted_unique?(_), do: false

  defp non_empty_string?(value), do: is_binary(value) and value != ""

  defp optional_non_empty_string?(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} -> non_empty_string?(value)
      :error -> true
    end
  end

  defp absolute_uri?(uri) when is_binary(uri) and uri != "" do
    case URI.new(uri) do
      {:ok, %URI{scheme: scheme}} when is_binary(scheme) and scheme != "" -> true
      _ -> false
    end
  end

  defp absolute_uri?(_), do: false

  defp string_field(card, field) do
    if non_empty_string?(Map.get(card, field)), do: :ok, else: {:error, :invalid_agent_card}
  end

  defp optional_string_field(card, field) do
    case Map.fetch(card, field) do
      {:ok, value} -> if non_empty_string?(value), do: :ok, else: {:error, :invalid_agent_card}
      :error -> :ok
    end
  end

  defp exact_field(card, field, expected) do
    if Map.get(card, field) == expected, do: :ok, else: {:error, :invalid_agent_card}
  end

  defp enum_field(card, field, allowed) do
    if Map.get(card, field) in allowed, do: :ok, else: {:error, :invalid_agent_card}
  end

  defp regex_field(card, field, regex) do
    value = Map.get(card, field)

    if is_binary(value) and Regex.match?(regex, value) do
      :ok
    else
      {:error, :invalid_agent_card}
    end
  end

  defp all_ok(checks) do
    if Enum.all?(checks, &(&1 == :ok)), do: :ok, else: {:error, :invalid_agent_card}
  end

  defp parse_timestamp(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _} -> {:ok, datetime}
      {:error, _} -> {:error, :invalid_agent_card}
    end
  end

  defp parse_timestamp(_), do: {:error, :invalid_agent_card}

  defp sha256_hex(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
end
