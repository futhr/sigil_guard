defmodule SigilGuard.Attestation do
  @moduledoc """
  Agent Trust attestation facade and reserved metadata helpers.

  The `_agent_trust` and `_agent_confirmation` keys carry SigilGuard trust
  evidence on guarded payloads. These helpers attach and fetch that metadata
  while `strip_metadata/1` applies the attestation digest strip rule before payload
  digest computation.

  ## Examples

      request = %{"method" => "tools/call", "params" => %{"name" => "read_file"}}
      envelope = %{"payload" => "base64url-payload", "signatures" => []}

      request = SigilGuard.Attestation.attach(request, envelope)
      {:ok, ^envelope} = SigilGuard.Attestation.fetch(request)

      stripped = SigilGuard.Attestation.strip_metadata(request)
      :error = SigilGuard.Attestation.fetch(stripped)
  """

  alias SigilGuard.Attestation.AgentPredicate
  alias SigilGuard.Attestation.Digest
  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Attestation.Statement
  alias SigilGuard.Audit.Evidence
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.Context
  alias SigilGuard.ReplayStore
  alias SigilGuard.TrustProfile

  @trust_key "_agent_trust"
  @trust_atom_key :_agent_trust
  @confirmation_key "_agent_confirmation"
  @confirmation_atom_key :_agent_confirmation
  @confirmation_token_key "confirmation_token"
  @confirmation_token_atom_key :confirmation_token
  @sha256_regex ~r/^[0-9a-f]{64}$/

  @strip_keys [
    @trust_key,
    @trust_atom_key,
    @confirmation_key,
    @confirmation_atom_key,
    @confirmation_token_key,
    @confirmation_token_atom_key
  ]

  @statement_types %{
    "tool_request" => :tool_request,
    "tool_result" => :tool_result,
    "model_ingress" => :model_ingress,
    "model_egress" => :model_egress,
    "repo_change" => :repo_change,
    "release" => :release,
    "agent_request" => :agent_request,
    "agent_response" => :agent_response
  }

  @phase_statement_types %{
    inbound_user: :model_ingress,
    tool_request: :tool_request,
    tool_result: :tool_result,
    outbound_model: :model_egress,
    repo_change: :repo_change
  }

  @type payload :: map()
  @type envelope :: map()
  @type sign_error ::
          :invalid_profile
          | :unknown_statement_type
          | :invalid_payload
          | :unsupported_number_range
          | :invalid_signer
          | :invalid_envelope

  @type verify_error ::
          :invalid_envelope
          | :invalid_payload_type
          | :invalid_base64
          | :duplicate_keyid
          | :missing_trust_bundle
          | :unknown_key_id
          | :invalid_signature
          | :pae_mismatch
          | :invalid_profile
          | :unsupported_profile_version
          | :unknown_statement_type
          | :digest_mismatch
          | :manifest_digest_mismatch
          | :unknown_manifest
          | :expired_attestation
          | :replay_detected
          | :replay_capacity_exceeded

  @type from_decision_error ::
          :unknown_statement_type
          | :invalid_payload
          | :invalid_context
          | :invalid_phase
          | :invalid_sink
          | :invalid_origin
          | :invalid_trust_level
          | :invalid_trust_zone
          | :invalid_audience
          | :invalid_metadata
          | :invalid_evidence

  @doc """
  Sign a decoded SigilGuard Statement as a DSSE envelope.
  """
  @spec sign(map(), module(), keyword()) :: {:ok, envelope()} | {:error, sign_error()}
  def sign(statement, signer, opts \\ [])

  def sign(statement, signer, opts) when is_map(statement) and is_atom(signer) do
    statement = apply_sign_options(statement, opts)

    with {:ok, statement} <- TrustProfile.validate(statement),
         {:ok, payload} <- JCS.encode(statement),
         {:ok, envelope} <- Envelope.sign(payload, signer, keyid: Keyword.get(opts, :keyid)) do
      {:ok, envelope}
    else
      {:error, :invalid_map} -> {:error, :invalid_payload}
      {:error, reason} -> {:error, reason}
    end
  end

  def sign(_, _, _), do: {:error, :invalid_payload}

  @doc """
  Build a SigilGuard Statement from a runtime decision, context, and payload.
  """
  @spec from_decision(SigilGuard.Decision.t(), Context.t() | map() | keyword(), keyword()) ::
          {:ok, map()} | {:error, from_decision_error()}
  def from_decision(decision, context, opts \\ [])

  def from_decision(%SigilGuard.Decision{} = decision, context, opts) when is_list(opts) do
    with {:ok, payload} <- required_payload(opts),
         :ok <- validate_evidence_option(opts),
         {:ok, context} <- normalize_context(context),
         {:ok, statement_type} <- decision_statement_type(context, opts),
         {:ok, actor_id} <- context_actor_id(context),
         {:ok, now} <- attestation_now(opts),
         {:ok, ttl_ms} <- attestation_ttl_ms(opts),
         {:ok, predicate_type} <- TrustProfile.predicate_type(statement_type),
         {:ok, digests} <- Digest.digests(statement_type, payload, context, opts),
         {:ok, predicate} <-
           decision_predicate(%{
             statement_type: statement_type,
             decision: decision,
             context: context,
             payload: payload,
             actor_id: actor_id,
             now: now,
             ttl_ms: ttl_ms,
             opts: opts
           }),
         {:ok, statement} <- Statement.build(predicate_type, predicate, digests),
         {:ok, statement} <- TrustProfile.validate(statement) do
      {:ok, statement}
    else
      {:error, :invalid_profile} -> {:error, :invalid_payload}
      {:error, :unsupported_number_range} -> {:error, :invalid_payload}
      {:error, reason} -> {:error, reason}
    end
  end

  def from_decision(_, _, _), do: {:error, :invalid_payload}

  @doc """
  Verify a DSSE-wrapped SigilGuard Statement.

  `trust_material` maps key ids to raw or encoded Ed25519 public keys. Pass
  `:payload` and `:context` to recompute action, payload, and context digests.
  Pass `consume: true` to consume the predicate nonce with `SigilGuard.ReplayStore`.
  """
  @spec verify(envelope(), map(), keyword()) :: {:ok, map()} | {:error, verify_error()}
  def verify(envelope, trust_material, opts \\ [])

  def verify(envelope, trust_material, opts)
      when is_map(trust_material) and map_size(trust_material) > 0 do
    with {:ok, payload} <- unsigned_payload(envelope),
         :ok <- expected_payload_sha256(payload, opts),
         {:ok, verified_payload} <- Envelope.verify(envelope, trust_material),
         :ok <- require_same_payload(payload, verified_payload),
         {:ok, statement} <- decode_statement(verified_payload),
         {:ok, statement} <- TrustProfile.validate(statement),
         :ok <- maybe_verify_digests(statement, opts),
         :ok <- validate_freshness(statement, opts),
         :ok <- maybe_consume_nonce(statement, opts) do
      {:ok, statement}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  def verify(_, _, _), do: {:error, :missing_trust_bundle}

  @doc """
  Attach an attestation envelope under the reserved `_agent_trust` key.

  Raises `ArgumentError` when `payload` is not a map.
  """
  @spec attach(payload(), envelope()) :: payload()
  def attach(payload, envelope) when is_map(payload) and is_map(envelope) do
    Map.put(payload, @trust_key, envelope)
  end

  def attach(payload, envelope) when is_map(payload) and not is_map(envelope) do
    raise ArgumentError, "expected attestation envelope to be a map"
  end

  def attach(_, _) do
    raise ArgumentError, "expected attestation payload to be a map"
  end

  @doc """
  Fetch an attestation envelope from `_agent_trust`.

  Both string and atom keys are accepted. Returns `:error` when the key is
  absent or the value is not a map.
  """
  @spec fetch(payload()) :: {:ok, envelope()} | :error
  def fetch(payload) when is_map(payload),
    do: fetch_map_metadata(payload, @trust_key, @trust_atom_key)

  def fetch(_), do: :error

  @doc """
  Attach a confirmation token under the reserved `_agent_confirmation` key.

  Raises `ArgumentError` when `payload` is not a map.
  """
  @spec attach_confirmation(payload(), String.t()) :: payload()
  def attach_confirmation(payload, token) when is_map(payload) and is_binary(token) do
    Map.put(payload, @confirmation_key, token)
  end

  def attach_confirmation(payload, _) when is_map(payload) do
    raise ArgumentError, "expected confirmation token to be a string"
  end

  def attach_confirmation(_, _) do
    raise ArgumentError, "expected attestation payload to be a map"
  end

  @doc """
  Fetch a confirmation token from `_agent_confirmation`.

  Both string and atom keys are accepted. Returns `:error` when the key is
  absent or the value is not a string.
  """
  @spec fetch_confirmation(payload()) :: {:ok, String.t()} | :error
  def fetch_confirmation(payload) when is_map(payload) do
    fetch_string_metadata(payload, @confirmation_key, @confirmation_atom_key)
  end

  def fetch_confirmation(_), do: :error

  @doc """
  Apply the attestation metadata strip rule.

  The reserved `_agent_trust`, `_agent_confirmation`, and `confirmation_token`
  keys are removed at the payload root and inside the map under `params` in
  both atom and string forms. Deeper nested occurrences are left untouched.
  """
  @spec strip_metadata(term()) :: term()
  def strip_metadata(payload) when is_map(payload) do
    payload
    |> Map.drop(@strip_keys)
    |> strip_params_metadata(:params)
    |> strip_params_metadata("params")
  end

  def strip_metadata(payload) when is_list(payload) do
    Enum.map(payload, fn
      item when is_map(item) -> strip_metadata(item)
      item -> item
    end)
  end

  def strip_metadata(payload), do: payload

  defp strip_params_metadata(payload, params_key) do
    case Map.get(payload, params_key) do
      params when is_map(params) -> Map.put(payload, params_key, Map.drop(params, @strip_keys))
      _ -> payload
    end
  end

  defp fetch_map_metadata(payload, string_key, atom_key) do
    case fetch_metadata(payload, string_key, atom_key) do
      {:ok, value} when is_map(value) -> {:ok, value}
      _ -> :error
    end
  end

  defp fetch_string_metadata(payload, string_key, atom_key) do
    case fetch_metadata(payload, string_key, atom_key) do
      {:ok, value} when is_binary(value) -> {:ok, value}
      _ -> :error
    end
  end

  defp fetch_metadata(payload, string_key, atom_key) do
    case Map.fetch(payload, string_key) do
      {:ok, value} -> {:ok, value}
      :error -> Map.fetch(payload, atom_key)
    end
  end

  defp apply_sign_options(statement, opts) do
    statement
    |> maybe_put_predicate("issued_at", issued_at_option(opts))
    |> maybe_put_predicate("nonce", Keyword.get(opts, :nonce))
  end

  defp issued_at_option(opts) do
    case Keyword.fetch(opts, :now) do
      {:ok, %DateTime{} = now} -> DateTime.to_iso8601(now)
      {:ok, now} when is_binary(now) -> now
      {:ok, _} -> nil
      :error -> nil
    end
  end

  defp maybe_put_predicate(statement, _, nil), do: statement

  defp maybe_put_predicate(statement, key, value) do
    predicate = Map.get(statement, "predicate", %{})
    Map.put(statement, "predicate", Map.put(predicate, key, value))
  end

  defp required_payload(opts) do
    case Keyword.fetch(opts, :payload) do
      {:ok, payload} when is_map(payload) -> {:ok, payload}
      {:ok, _} -> {:error, :invalid_payload}
      :error -> {:error, :invalid_payload}
    end
  end

  defp validate_evidence_option(opts) do
    case Keyword.fetch(opts, :evidence) do
      :error -> :ok
      {:ok, evidence} -> Evidence.validate(evidence)
    end
  end

  defp normalize_context(%Context{} = context) do
    with :ok <- Context.validate(context), do: {:ok, context}
  end

  defp normalize_context(context) when is_map(context) or is_list(context) do
    normalized = Context.new(context)

    with :ok <- Context.validate(normalized), do: {:ok, normalized}
  end

  defp normalize_context(_), do: {:error, :invalid_context}

  defp decision_statement_type(context, opts) do
    case Keyword.fetch(opts, :statement_type) do
      {:ok, statement_type} -> normalize_statement_type(statement_type)
      :error -> Map.fetch(@phase_statement_types, context.phase)
    end
  end

  defp normalize_statement_type(statement_type) when is_atom(statement_type) do
    if statement_type in Map.values(@statement_types) do
      {:ok, statement_type}
    else
      {:error, :unknown_statement_type}
    end
  end

  defp normalize_statement_type(statement_type) when is_binary(statement_type) do
    case Map.fetch(@statement_types, statement_type) do
      {:ok, statement_type} -> {:ok, statement_type}
      :error -> {:error, :unknown_statement_type}
    end
  end

  defp normalize_statement_type(_), do: {:error, :unknown_statement_type}

  defp context_actor_id(%Context{actor: actor}) when is_binary(actor) and actor != "",
    do: {:ok, actor}

  defp context_actor_id(%Context{identity: identity}) when is_binary(identity) and identity != "",
    do: {:ok, identity}

  defp context_actor_id(_), do: {:error, :invalid_payload}

  defp attestation_now(opts) do
    case Keyword.get(opts, :now, DateTime.utc_now()) do
      %DateTime{} = now -> {:ok, now}
      _ -> {:error, :invalid_payload}
    end
  end

  defp attestation_ttl_ms(opts) do
    ttl_ms =
      Keyword.get(opts, :ttl_ms, Application.get_env(:sigil_guard, :attestation_ttl_ms, 300_000))

    if is_integer(ttl_ms) and ttl_ms > 0 do
      {:ok, ttl_ms}
    else
      {:error, :invalid_payload}
    end
  end

  defp decision_predicate(source) do
    predicate =
      %{
        "profile" => TrustProfile.profile_id(),
        "statement_type" => Atom.to_string(source.statement_type),
        "actor" => %{
          "id" => source.actor_id,
          "trust_level" => Atom.to_string(source.context.trust_level)
        },
        "verdict" => predicate_verdict(source.decision),
        "action" => Atom.to_string(source.decision.action),
        "risk_level" => Atom.to_string(source.decision.risk_level),
        "issued_at" => DateTime.to_iso8601(source.now),
        "expires_at" =>
          DateTime.add(source.now, source.ttl_ms, :millisecond) |> DateTime.to_iso8601()
      }
      |> maybe_put("reason", source.decision.reason)
      |> maybe_put("nonce", Keyword.get(source.opts, :nonce))
      |> maybe_put("evidence", Keyword.get(source.opts, :evidence))

    with {:ok, extension} <- predicate_extension(source, predicate) do
      {:ok, Map.merge(predicate, extension)}
    end
  end

  defp predicate_verdict(%{action: :quarantine}), do: "quarantine"
  defp predicate_verdict(%{verdict: :allowed}), do: "allow"
  defp predicate_verdict(%{verdict: :blocked}), do: "block"
  defp predicate_verdict(%{verdict: {:confirm, _}}), do: "confirm"
  defp predicate_verdict(_), do: "block"

  defp predicate_extension(%{statement_type: :tool_request} = source, _) do
    {:ok,
     %{}
     |> maybe_put("tool", tool_predicate(source))
     |> maybe_put("resource", resource_predicate(source))}
  end

  defp predicate_extension(%{statement_type: :tool_result} = source, _) do
    with {:ok, request_action_digest} <- required_digest(source.opts, :request_action_digest),
         {:ok, output_schema_sha256} <- optional_digest(source.opts, :output_schema_sha256),
         {:ok, quarantine} <- quarantine_predicate(source),
         {:ok, scanner} <- scanner_predicate(source) do
      {:ok,
       %{
         "boundary" => %{"sink" => Atom.to_string(source.context.sink)},
         "request_action_digest" => request_action_digest,
         "quarantine" => quarantine,
         "scanner" => scanner
       }
       |> maybe_put("output_schema_sha256", output_schema_sha256)}
    end
  end

  defp predicate_extension(%{statement_type: :agent_request} = source, predicate) do
    opts =
      source.opts
      |> Keyword.put_new(:peer_trust, source.context.trust_level)
      |> Keyword.put(:verdict, predicate["verdict"])

    AgentPredicate.build_request(source.payload, opts)
  end

  defp predicate_extension(%{statement_type: :agent_response} = source, _) do
    opts =
      source.opts
      |> Keyword.put_new(:peer_trust, source.context.trust_level)
      |> Keyword.put_new(:quarantined, source.decision.action == :quarantine)

    AgentPredicate.build_response(source.payload, opts)
  end

  defp predicate_extension(_, _), do: {:ok, %{}}

  defp tool_predicate(source) do
    %{}
    |> maybe_put("name", source.context.tool)
    |> maybe_put("mcp_server", source.context.mcp_server)
    |> maybe_put("manifest_digest", Keyword.get(source.opts, :manifest_digest))
  end

  defp resource_predicate(source) do
    scope =
      source.opts
      |> Keyword.get(:scopes)
      |> scope_string()

    %{}
    |> maybe_put("uri", Keyword.get(source.opts, :resource) || source.context.resource_uri)
    |> maybe_put(
      "audience",
      Keyword.get(source.opts, :audience) || source.context.intended_audience
    )
    |> maybe_put("scope", scope)
  end

  defp scope_string(scopes) when is_list(scopes) do
    scopes
    |> Enum.filter(&is_binary/1)
    |> Enum.sort()
    |> Enum.join(" ")
    |> blank_to_nil()
  end

  defp scope_string(scope) when is_binary(scope), do: blank_to_nil(scope)
  defp scope_string(_), do: nil

  defp blank_to_nil(""), do: nil
  defp blank_to_nil(value), do: value

  defp required_digest(opts, key) do
    case Keyword.fetch(opts, key) do
      {:ok, digest} when is_binary(digest) ->
        if Regex.match?(@sha256_regex, digest),
          do: {:ok, digest},
          else: {:error, :invalid_payload}

      _ ->
        {:error, :invalid_payload}
    end
  end

  defp optional_digest(opts, key) do
    case Keyword.fetch(opts, key) do
      {:ok, digest} when is_binary(digest) ->
        if Regex.match?(@sha256_regex, digest),
          do: {:ok, digest},
          else: {:error, :invalid_payload}

      {:ok, nil} ->
        {:ok, nil}

      {:ok, _} ->
        {:error, :invalid_payload}

      :error ->
        {:ok, nil}
    end
  end

  defp quarantine_predicate(source) do
    status =
      source.opts
      |> Keyword.get(:quarantine_status, source.decision.audit_metadata[:quarantine_status])
      |> quarantine_status()

    indicator_ids =
      source.opts
      |> Keyword.get(
        :indicator_ids,
        source.decision.audit_metadata[:scanner_summary][:indicator_ids]
      )
      |> normalize_indicator_ids(source.decision.indicators)

    {:ok, %{"status" => status, "indicator_ids" => indicator_ids}}
  end

  defp quarantine_status(:quarantined), do: "quarantined"
  defp quarantine_status(:released_sanitized), do: "released_sanitized"
  defp quarantine_status(_), do: "none"

  defp normalize_indicator_ids(ids, _) when is_list(ids) do
    ids
    |> Enum.filter(&is_binary/1)
    |> Enum.sort()
  end

  defp normalize_indicator_ids(_, indicators) when is_list(indicators) do
    indicators
    |> Enum.map(&(Map.get(&1, :id) || Map.get(&1, "id")))
    |> Enum.filter(&is_binary/1)
    |> Enum.sort()
  end

  defp normalize_indicator_ids(_, _), do: []

  defp scanner_predicate(source) do
    summary = source.decision.audit_metadata[:scanner_summary] || %{}

    hit_count =
      source.opts
      |> Keyword.get(
        :scanner_hit_count,
        Map.get(summary, :hit_count, length(source.decision.hits))
      )

    redacted = Keyword.get(source.opts, :redacted, source.decision.action == :redact)

    if is_integer(hit_count) and hit_count >= 0 and is_boolean(redacted) do
      {:ok, %{"hit_count" => hit_count, "redacted" => redacted}}
    else
      {:error, :invalid_payload}
    end
  end

  defp maybe_put(map, _, nil), do: map
  defp maybe_put(map, _, value) when is_map(value) and map_size(value) == 0, do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp unsigned_payload(envelope) do
    with {:ok, fields} <- envelope_fields(envelope),
         :ok <- require_payload_type(fields.payload_type),
         {:ok, signatures} <- signature_fields(fields.signatures),
         :ok <- reject_duplicate_keyids(signatures) do
      decode_base64(fields.payload)
    end
  end

  defp envelope_fields(%{} = envelope) do
    payload = field(envelope, "payload")
    payload_type = field(envelope, "payloadType")
    signatures = field(envelope, "signatures")

    if is_binary(payload) and is_binary(payload_type) and is_list(signatures) and
         signatures != [] do
      {:ok, %{payload: payload, payload_type: payload_type, signatures: signatures}}
    else
      {:error, :invalid_envelope}
    end
  end

  defp envelope_fields(_), do: {:error, :invalid_envelope}

  defp field(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} -> value
      :error -> Map.get(map, atom_key(key))
    end
  end

  defp atom_key("keyid"), do: :keyid
  defp atom_key("payload"), do: :payload
  defp atom_key("payloadType"), do: :payloadType
  defp atom_key("sig"), do: :sig
  defp atom_key("signatures"), do: :signatures

  defp require_payload_type(type) do
    if type == Envelope.payload_type(), do: :ok, else: {:error, :invalid_payload_type}
  end

  defp signature_fields(signatures) do
    result =
      Enum.reduce_while(signatures, {:ok, []}, fn signature, {:ok, parsed} ->
        case signature_field(signature) do
          {:ok, fields} -> {:cont, {:ok, [fields | parsed]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)

    case result do
      {:ok, parsed} -> {:ok, Enum.reverse(parsed)}
      {:error, reason} -> {:error, reason}
    end
  end

  defp signature_field(%{} = signature) do
    keyid = field(signature, "keyid")
    sig = field(signature, "sig")

    if is_binary(keyid) and keyid != "" and is_binary(sig) do
      {:ok, %{keyid: keyid, sig: sig}}
    else
      {:error, :invalid_envelope}
    end
  end

  defp signature_field(_), do: {:error, :invalid_envelope}

  defp reject_duplicate_keyids(signatures) do
    keyids = Enum.map(signatures, & &1.keyid)

    if Enum.uniq(keyids) == keyids, do: :ok, else: {:error, :duplicate_keyid}
  end

  defp expected_payload_sha256(payload, opts) do
    case Keyword.fetch(opts, :expected_payload_sha256) do
      {:ok, expected} when is_binary(expected) ->
        actual = Base.encode16(:crypto.hash(:sha256, payload), case: :lower)

        if actual == expected, do: :ok, else: {:error, :pae_mismatch}

      {:ok, _} ->
        {:error, :pae_mismatch}

      :error ->
        :ok
    end
  end

  defp require_same_payload(payload, payload), do: :ok
  defp require_same_payload(_, _), do: {:error, :pae_mismatch}

  defp decode_statement(payload) do
    case SigilGuard.Canonical.JSON.decode(payload) do
      {:ok, statement} when is_map(statement) ->
        with :ok <- SigilGuard.Limits.check(statement), do: {:ok, statement}

      {:ok, _} ->
        {:error, :invalid_profile}

      {:error, _} ->
        {:error, :invalid_profile}
    end
  end

  defp maybe_verify_digests(statement, opts) do
    if Keyword.has_key?(opts, :payload) and Keyword.has_key?(opts, :context) do
      verify_digests(statement, opts)
    else
      :ok
    end
  end

  defp verify_digests(statement, opts) do
    with {:ok, statement_type} <- statement_type(statement),
         {:ok, expected} <-
           Digest.digests(
             statement_type,
             Keyword.fetch!(opts, :payload),
             Keyword.fetch!(opts, :context),
             opts
           ) do
      compare_subject_digests(statement, expected)
    end
  end

  defp statement_type(statement) do
    case Map.fetch(@statement_types, get_in(statement, ["predicate", "statement_type"])) do
      {:ok, statement_type} -> {:ok, statement_type}
      :error -> {:error, :unknown_statement_type}
    end
  end

  defp compare_subject_digests(statement, expected) do
    actual =
      statement["subject"]
      |> Enum.map(fn entry -> {entry["name"], get_in(entry, ["digest", "sha256"])} end)
      |> Map.new()

    with :ok <- compare_digest(actual, expected, "action"),
         :ok <- compare_digest(actual, expected, "payload"),
         :ok <- compare_digest(actual, expected, "context") do
      compare_manifest_digest(actual, expected)
    end
  end

  defp compare_digest(actual, expected, name) do
    if Map.get(actual, name) == Map.get(expected, name) do
      :ok
    else
      {:error, :digest_mismatch}
    end
  end

  defp compare_manifest_digest(actual, expected) do
    case {Map.fetch(actual, "manifest"), Map.fetch(expected, "manifest")} do
      {:error, :error} -> :ok
      {{:ok, digest}, {:ok, digest}} -> :ok
      {{:ok, _}, :error} -> {:error, :unknown_manifest}
      _ -> {:error, :manifest_digest_mismatch}
    end
  end

  defp validate_freshness(statement, opts) do
    with {:ok, now} <- verify_now(opts),
         {:ok, max_skew_ms} <- max_skew_ms(opts),
         {:ok, issued_at, expires_at} <- freshness_times(statement) do
      cond do
        not DateTime.before?(issued_at, expires_at) ->
          {:error, :invalid_payload}

        DateTime.after?(now, DateTime.add(expires_at, max_skew_ms, :millisecond)) ->
          {:error, :expired_attestation}

        DateTime.after?(issued_at, DateTime.add(now, max_skew_ms, :millisecond)) ->
          {:error, :expired_attestation}

        true ->
          :ok
      end
    end
  end

  defp verify_now(opts) do
    case Keyword.get(opts, :now, DateTime.utc_now()) do
      %DateTime{} = now -> {:ok, now}
      _ -> {:error, :invalid_payload}
    end
  end

  defp max_skew_ms(opts) do
    configured_non_negative_integer(opts, :max_skew_ms, :max_skew_ms, 60_000)
  end

  defp freshness_times(statement) do
    predicate = statement["predicate"]

    with {:ok, issued_at} <- parse_required_datetime(Map.get(predicate, "issued_at")),
         {:ok, expires_at} <- parse_required_datetime(Map.get(predicate, "expires_at")) do
      {:ok, issued_at, expires_at}
    end
  end

  defp parse_required_datetime(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _} -> {:ok, datetime}
      {:error, _} -> {:error, :invalid_payload}
    end
  end

  defp parse_required_datetime(_), do: {:error, :invalid_payload}

  defp maybe_consume_nonce(statement, opts) do
    if Keyword.get(opts, :replay, Keyword.get(opts, :consume, false)) do
      consume_nonce(statement, opts)
    else
      :ok
    end
  end

  defp consume_nonce(statement, opts) do
    predicate = statement["predicate"]

    with actor when is_binary(actor) <- actor_id(predicate),
         nonce when is_binary(nonce) <- Map.get(predicate, "nonce"),
         {:ok, ttl_ms} <- replay_ttl_ms(predicate, opts) do
      ReplayStore.check_and_put("attestation:" <> actor, nonce, ttl_ms)
    else
      _ -> {:error, :invalid_payload}
    end
  end

  defp replay_ttl_ms(predicate, opts) do
    with {:ok, required} <- remaining_lifetime_ms(predicate, opts),
         {:ok, configured} <- requested_replay_ttl(opts) do
      {:ok, max(required, configured)}
    end
  end

  defp requested_replay_ttl(opts) do
    key = if Keyword.has_key?(opts, :replay_ttl_ms), do: :replay_ttl_ms, else: :ttl_ms
    configured_positive_integer(opts, key, :replay_ttl_ms, 300_000)
  end

  defp remaining_lifetime_ms(predicate, opts) do
    with {:ok, now} <- verify_now(opts),
         {:ok, expires_at} <- parse_required_datetime(Map.get(predicate, "expires_at")),
         {:ok, skew} <- max_skew_ms(opts) do
      {:ok, max(DateTime.diff(expires_at, now, :millisecond) + skew + 1, 1)}
    end
  end

  defp actor_id(predicate) do
    case Map.get(predicate, "actor") do
      %{"id" => id} when is_binary(id) -> id
      _ -> nil
    end
  end

  defp configured_positive_integer(opts, opt_key, config_key, default) do
    value = Keyword.get(opts, opt_key, Application.get_env(:sigil_guard, config_key, default))

    if is_integer(value) and value > 0 do
      {:ok, value}
    else
      {:error, :invalid_payload}
    end
  end

  defp configured_non_negative_integer(opts, opt_key, config_key, default) do
    value = Keyword.get(opts, opt_key, Application.get_env(:sigil_guard, config_key, default))

    if is_integer(value) and value >= 0 do
      {:ok, value}
    else
      {:error, :invalid_payload}
    end
  end

  defp decode_base64(value) when is_binary(value) do
    with :error <- Base.url_decode64(value, padding: false),
         :error <- Base.url_decode64(value, padding: true),
         :error <- Base.decode64(value, padding: false),
         :error <- Base.decode64(value, padding: true) do
      {:error, :invalid_base64}
    end
  end
end
