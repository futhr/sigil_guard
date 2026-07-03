defmodule SigilGuard.TrustBundle.Verify do
  @moduledoc """
  Pure verification pipeline for SP.02 trust-bundle envelopes.

  This module validates one DSSE-signed trust-bundle document. It does not
  load sources, cache snapshots, walk root-rotation chains, or write
  quarantine records; those responsibilities live in later pipeline stages.
  """

  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.TrustBundle
  alias SigilGuard.TrustBundle.Cache
  alias SigilGuard.TrustBundle.Schema

  @ed25519_signature_bytes 64
  @default_max_skew_ms 60_000

  @type verify_error :: TrustBundle.verify_error()

  @doc """
  Verify a decoded trust-bundle DSSE envelope.
  """
  @spec verify(map(), keyword()) :: {:ok, TrustBundle.t()} | {:error, verify_error()}
  def verify(envelope, opts \\ [])

  def verify(envelope, opts) when is_map(envelope) and is_list(opts) do
    with {:ok, fields} <- envelope_fields(envelope),
         :ok <- require_payload_type(fields.payload_type),
         {:ok, signatures} <- signature_fields(fields.signatures),
         :ok <- reject_duplicate_keyids(signatures),
         {:ok, payload} <- decode_base64(fields.payload),
         {:ok, document} <- decode_document(payload),
         {:ok, :bundle, document} <- Schema.validate(document),
         :ok <- verify_rotation_chain(document, opts),
         {:ok, context} <- verification_context(document, signatures, opts),
         :ok <- reject_revoked_signatures(signatures, context.revoked_keyids),
         :ok <- verify_threshold(signatures, context, fields.payload_type, payload),
         :ok <- verify_freshness(document, context.role, opts) do
      {:ok, trust_bundle(envelope, document, payload, source(opts))}
    else
      {:ok, :rotation, _} -> {:error, :invalid_bundle_format}
      {:error, reason} -> {:error, reason}
    end
  end

  def verify(_, _), do: {:error, :invalid_envelope}

  defp envelope_fields(%{} = envelope) do
    payload = field(envelope, "payload")
    payload_type = field(envelope, "payloadType")
    signatures = field(envelope, "signatures")

    valid? =
      is_binary(payload) and is_binary(payload_type) and is_list(signatures) and signatures != []

    if valid? do
      {:ok, %{payload: payload, payload_type: payload_type, signatures: signatures}}
    else
      {:error, :invalid_envelope}
    end
  end

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

  defp require_payload_type(payload_type) do
    if payload_type == Envelope.payload_type() do
      :ok
    else
      {:error, :invalid_payload_type}
    end
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

    if Enum.uniq(keyids) == keyids do
      :ok
    else
      {:error, :duplicate_keyid}
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

  defp decode_base64(_), do: {:error, :invalid_base64}

  defp decode_document(payload) do
    case Jason.decode(payload) do
      {:ok, %{} = document} -> {:ok, document}
      _ -> {:error, :invalid_bundle_format}
    end
  end

  defp verification_context(document, signatures, opts) do
    with {:ok, role} <- bundle_role(document),
         {:ok, public_keys} <- public_keys(document),
         {:ok, revoked_keyids} <- revoked_keyids(document),
         {:ok, threshold} <- threshold(role, opts),
         :ok <- known_authorized_signer?(signatures, role, revoked_keyids) do
      {:ok,
       %{
         role: role,
         public_keys: public_keys,
         revoked_keyids: revoked_keyids,
         threshold: threshold
       }}
    end
  end

  defp bundle_role(%{"roles" => %{"delegates" => delegates}}) do
    case Enum.find(delegates, &(Map.get(&1, "name") == "bundle")) do
      %{} = role -> {:ok, role}
      nil -> {:error, :unknown_role}
    end
  end

  defp bundle_role(_), do: {:error, :unknown_role}

  defp public_keys(%{"keys" => keys}) do
    public_keys =
      Map.new(keys, fn {keyid, descriptor} ->
        {:ok, public_key} = decode_base64(Map.fetch!(descriptor, "public_key"))
        {keyid, public_key}
      end)

    {:ok, public_keys}
  end

  defp verify_rotation_chain(document, opts) do
    with {:ok, genesis} <- genesis_root(document, opts) do
      walk_rotation_chain(document, genesis)
    end
  end

  defp genesis_root(document, opts) do
    case Keyword.fetch(opts, :genesis_root) do
      {:ok, genesis} ->
        normalize_genesis_root(genesis)

      :error ->
        cached_or_current_root(document)
    end
  end

  defp cached_or_current_root(%{"bundle_id" => bundle_id} = document) do
    case Cache.root_pin(bundle_id) do
      {:ok, pin} -> {:ok, pin}
      :error -> current_root(document)
    end
  end

  defp current_root(document) do
    with {:ok, keys} <- public_keys(document),
         %{} = root <- get_in(document, ["roles", "root"]) do
      {:ok,
       %{
         version: positive_integer!(Map.fetch!(root, "version")),
         threshold: Map.fetch!(root, "threshold"),
         keyids: Map.fetch!(root, "keyids"),
         keys: keys
       }}
    end
  end

  defp normalize_genesis_root(%{
         version: version,
         threshold: threshold,
         keyids: keyids,
         keys: keys
       })
       when is_integer(version) and version > 0 and is_integer(threshold) and threshold > 0 and
              is_list(keyids) and is_map(keys) do
    {:ok, %{version: version, threshold: threshold, keyids: keyids, keys: keys}}
  end

  defp normalize_genesis_root(_), do: {:error, :invalid_bundle_format}

  defp walk_rotation_chain(document, genesis) do
    current_root = get_in(document, ["roles", "root"])
    current_version = positive_integer!(Map.fetch!(current_root, "version"))
    chain = Map.get(document, "rotation_chain", [])

    cond do
      current_version == genesis.version ->
        if chain == [], do: :ok, else: {:error, :invalid_bundle_format}

      current_version < genesis.version ->
        {:error, :sequence_below_floor}

      true ->
        with {:ok, terminal} <- walk_rotations(chain, genesis, Map.fetch!(document, "bundle_id")) do
          terminal_root_matches?(terminal, current_root)
        end
    end
  end

  defp walk_rotations([], _, _), do: {:error, :invalid_bundle_format}

  defp walk_rotations(chain, genesis, bundle_id) when is_list(chain) do
    result =
      Enum.reduce_while(chain, {:ok, genesis, %{}}, fn envelope, {:ok, previous, seen} ->
        with {:ok, version, digest} <- rotation_version_digest(envelope),
             :ok <- reject_forked_rotation(bundle_id, version, digest, seen),
             {:ok, next_root} <- verify_rotation(envelope, previous) do
          {:cont, {:ok, next_root, Map.put(seen, version, digest)}}
        else
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)

    case result do
      {:ok, terminal, _} -> {:ok, terminal}
      {:error, reason} -> {:error, reason}
    end
  end

  defp rotation_version_digest(envelope) do
    with {:ok, fields} <- envelope_fields(envelope),
         {:ok, payload} <- decode_base64(fields.payload),
         {:ok, document} <- decode_document(payload),
         {:ok, :rotation, document} <- Schema.validate(document) do
      {:ok, positive_integer!(Map.fetch!(document, "root_version")), document_digest(document)}
    else
      {:ok, :bundle, _} -> {:error, :invalid_bundle_format}
      {:error, reason} -> {:error, reason}
    end
  end

  defp reject_forked_rotation(bundle_id, version, digest, seen) do
    cond do
      Map.get(seen, version) not in [nil, digest] ->
        {:error, :forked_root_chain}

      cached_rotation_forked?(bundle_id, version, digest) ->
        {:error, :forked_root_chain}

      true ->
        :ok
    end
  end

  defp cached_rotation_forked?(bundle_id, version, digest) do
    case Cache.rotation_digest(bundle_id, version) do
      {:ok, ^digest} -> false
      {:ok, _} -> true
      :error -> false
    end
  end

  defp verify_rotation(envelope, previous) do
    with {:ok, fields} <- envelope_fields(envelope),
         :ok <- require_payload_type(fields.payload_type),
         {:ok, signatures} <- signature_fields(fields.signatures),
         :ok <- reject_duplicate_keyids(signatures),
         {:ok, payload} <- decode_base64(fields.payload),
         {:ok, document} <- decode_document(payload),
         {:ok, :rotation, document} <- Schema.validate(document),
         :ok <- next_root_version?(document, previous),
         {:ok, next} <- rotation_root(document),
         :ok <- verify_rotation_threshold(signatures, previous, fields.payload_type, payload),
         :ok <- verify_rotation_threshold(signatures, next, fields.payload_type, payload) do
      {:ok, next}
    else
      {:ok, :bundle, _} -> {:error, :invalid_bundle_format}
      {:error, :threshold_not_met} -> {:error, :rotation_below_threshold}
      {:error, :unknown_key_id} -> {:error, :rotation_below_threshold}
      {:error, reason} -> {:error, reason}
    end
  end

  defp next_root_version?(document, previous) do
    root_version = positive_integer!(Map.fetch!(document, "root_version"))

    if root_version == previous.version + 1 do
      :ok
    else
      {:error, :invalid_bundle_format}
    end
  end

  defp rotation_root(document) do
    with {:ok, keys} <- public_keys(document),
         %{} = root <- get_in(document, ["roles", "root"]) do
      {:ok,
       %{
         version: positive_integer!(Map.fetch!(root, "version")),
         threshold: Map.fetch!(root, "threshold"),
         keyids: Map.fetch!(root, "keyids"),
         keys: keys,
         descriptor: root,
         digest: document_digest(document)
       }}
    end
  end

  defp verify_rotation_threshold(signatures, root, payload_type, payload) do
    context = %{
      role: %{"keyids" => root.keyids},
      public_keys: root.keys,
      threshold: root.threshold
    }

    verify_threshold(signatures, context, payload_type, payload)
  end

  defp terminal_root_matches?(terminal, current_root) do
    if Map.take(terminal.descriptor, ~w(keyids threshold version expires_at)) ==
         Map.take(current_root, ~w(keyids threshold version expires_at)) do
      :ok
    else
      {:error, :invalid_bundle_format}
    end
  end

  defp document_digest(document) do
    {:ok, bytes} = JCS.encode(document)
    Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
  end

  defp revoked_keyids(document) do
    revoked =
      document
      |> Map.get("revocations", [])
      |> Enum.filter(&(Map.get(&1, "kind") == "key"))
      |> Enum.map(&Map.fetch!(&1, "id"))
      |> MapSet.new()

    {:ok, revoked}
  end

  defp threshold(role, opts) do
    if Keyword.get(opts, :enforce_declared_threshold, false) do
      {:ok, Map.fetch!(role, "threshold")}
    else
      {:ok, 1}
    end
  end

  defp known_authorized_signer?(signatures, role, revoked_keyids) do
    authorized = MapSet.new(Map.fetch!(role, "keyids"))

    known? =
      Enum.any?(signatures, fn signature ->
        MapSet.member?(authorized, signature.keyid) or
          MapSet.member?(revoked_keyids, signature.keyid)
      end)

    if known?, do: :ok, else: {:error, :unknown_key_id}
  end

  defp reject_revoked_signatures(signatures, revoked_keyids) do
    if Enum.any?(signatures, &MapSet.member?(revoked_keyids, &1.keyid)) do
      {:error, :revoked_key}
    else
      :ok
    end
  end

  defp verify_threshold(signatures, context, payload_type, payload) do
    authorized = MapSet.new(Map.fetch!(context.role, "keyids"))
    pae = Envelope.pae(payload_type, payload)

    result =
      Enum.reduce_while(signatures, {:ok, MapSet.new()}, fn signature, {:ok, verified} ->
        verify_counted_signature(signature, authorized, context.public_keys, pae, verified)
      end)

    case result do
      {:ok, verified} -> threshold_met?(verified, context.threshold)
      {:error, reason} -> {:error, reason}
    end
  end

  defp threshold_met?(verified, threshold) do
    if MapSet.size(verified) >= threshold do
      :ok
    else
      {:error, :threshold_not_met}
    end
  end

  defp verify_counted_signature(signature, authorized, public_keys, pae, verified) do
    if MapSet.member?(authorized, signature.keyid) do
      case verify_signature(signature, public_keys, pae) do
        :ok -> {:cont, {:ok, MapSet.put(verified, signature.keyid)}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    else
      {:cont, {:ok, verified}}
    end
  end

  defp verify_signature(signature, public_keys, pae) do
    public_key = Map.fetch!(public_keys, signature.keyid)

    with {:ok, decoded_signature} <- decode_base64(signature.sig),
         :ok <- verify_ed25519(pae, decoded_signature, public_key) do
      :ok
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp verify_ed25519(pae, signature, public_key)
       when byte_size(signature) == @ed25519_signature_bytes do
    if :crypto.verify(:eddsa, :none, pae, signature, [public_key, :ed25519]) do
      :ok
    else
      {:error, :invalid_signature}
    end
  rescue
    _ -> {:error, :invalid_signature}
  end

  defp verify_ed25519(_, _, _), do: {:error, :invalid_signature}

  defp verify_freshness(document, bundle_role, opts) do
    with {:ok, now} <- now(opts),
         {:ok, max_skew_ms} <- max_skew_ms(opts),
         :ok <- document_fresh?(document, now, max_skew_ms),
         :ok <- role_fresh?(get_in(document, ["roles", "root"]), now, max_skew_ms) do
      role_fresh?(bundle_role, now, max_skew_ms)
    end
  end

  defp document_fresh?(document, now, max_skew_ms) do
    issued_at = parse_timestamp!(Map.fetch!(document, "issued_at"))
    expires_at = parse_timestamp!(Map.fetch!(document, "expires_at"))

    cond do
      DateTime.after?(now, DateTime.add(expires_at, max_skew_ms, :millisecond)) ->
        {:error, :bundle_expired}

      DateTime.after?(issued_at, DateTime.add(now, max_skew_ms, :millisecond)) ->
        {:error, :bundle_expired}

      true ->
        :ok
    end
  end

  defp role_fresh?(role, now, max_skew_ms) do
    expires_at = parse_timestamp!(Map.fetch!(role, "expires_at"))

    if DateTime.after?(now, DateTime.add(expires_at, max_skew_ms, :millisecond)) do
      {:error, :role_expired}
    else
      :ok
    end
  end

  defp now(opts) do
    case Keyword.get_lazy(opts, :now, fn -> DateTime.utc_now(:millisecond) end) do
      %DateTime{} = now -> {:ok, now}
      _ -> {:error, :invalid_bundle_format}
    end
  end

  defp max_skew_ms(opts) do
    case Keyword.get(opts, :max_skew_ms, @default_max_skew_ms) do
      max_skew_ms when is_integer(max_skew_ms) and max_skew_ms >= 0 ->
        {:ok, max_skew_ms}

      _ ->
        {:error, :invalid_bundle_format}
    end
  end

  defp parse_timestamp!(timestamp) do
    {:ok, datetime, 0} = DateTime.from_iso8601(timestamp)
    datetime
  end

  @spec source(keyword()) :: TrustBundle.source() | :dev
  defp source(opts) do
    case Keyword.get(opts, :source, :none) do
      :none -> :none
      :dev -> :dev
      {:file, path} when is_binary(path) -> {:file, path}
      {:priv, app, rel} when is_atom(app) and is_binary(rel) -> {:priv, app, rel}
      {:map, envelope} when is_map(envelope) -> {:map, envelope}
      {:binary, bytes} when is_binary(bytes) -> {:binary, bytes}
      _ -> :none
    end
  end

  defp trust_bundle(envelope, document, payload, source) do
    sequence = positive_integer!(Map.fetch!(document, "sequence"))
    root_version = positive_integer!(get_in(document, ["roles", "root", "version"]))

    %TrustBundle{
      bundle_id: Map.fetch!(document, "bundle_id"),
      sequence: sequence,
      root_version: root_version,
      digest: Base.encode16(:crypto.hash(:sha256, payload), case: :lower),
      document: document,
      envelope: envelope,
      dev?: dev?(document),
      source: source
    }
  end

  @spec positive_integer!(String.t()) :: pos_integer()
  defp positive_integer!(value), do: String.to_integer(value)

  defp dev?(document) do
    get_in(document, ["provenance", "issuer_class"]) == "dev"
  end
end
