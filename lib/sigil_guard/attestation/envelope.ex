defmodule SigilGuard.Attestation.Envelope do
  @moduledoc """
  DSSE envelope encoding, PAE construction, and Ed25519 verification.

  This module owns the v3 envelope byte contract. It signs and verifies
  opaque payload bytes; callers must not re-canonicalize payloads during
  signature verification.
  """

  @payload_type "application/vnd.sigilguard+json"
  @pae_prefix "DSSEv1"
  @ed25519_public_key_bytes 32
  @ed25519_signature_bytes 64

  @type envelope :: %{
          required(String.t()) => String.t() | [signature_entry()]
        }
  @type signature_entry :: %{
          required(String.t()) => String.t()
        }
  @type signer :: module() | {module(), String.t()}
  @type verify_error ::
          :invalid_envelope
          | :invalid_payload_type
          | :invalid_base64
          | :duplicate_keyid
          | :missing_trust_bundle
          | :unknown_key_id
          | :invalid_signature

  @doc """
  Return the SigilGuard DSSE payload type constant.
  """
  @spec payload_type() :: String.t()
  def payload_type, do: @payload_type

  @doc """
  Build DSSE Pre-Authentication Encoding bytes.
  """
  @spec pae(payload_type :: binary(), payload :: binary()) :: binary()
  def pae(payload_type \\ @payload_type, payload)
      when is_binary(payload_type) and is_binary(payload) do
    [
      @pae_prefix,
      " ",
      Integer.to_string(byte_size(payload_type)),
      " ",
      payload_type,
      " ",
      Integer.to_string(byte_size(payload)),
      " ",
      payload
    ]
    |> IO.iodata_to_binary()
  end

  @doc """
  Sign payload bytes with a single `SigilGuard.Signer` module.
  """
  @spec sign(binary(), module(), keyword()) ::
          {:ok, envelope()} | {:error, :invalid_envelope | :invalid_signer}
  def sign(payload, signer, opts \\ [])

  def sign(payload, signer, opts) when is_binary(payload) and is_atom(signer) do
    keyid = Keyword.get(opts, :keyid)
    sign_many(payload, [{signer, keyid}])
  end

  def sign(_, _, _), do: {:error, :invalid_envelope}

  @doc """
  Sign payload bytes with one or more signer modules.

  Each signer can be a module implementing `SigilGuard.Signer` or
  `{module, keyid}`. A nil keyid derives the SigilGuard-local
  `"sha256:" <> hex` key id from the signer's raw public key.
  """
  @spec sign_many(binary(), [signer()]) ::
          {:ok, envelope()} | {:error, :invalid_envelope | :invalid_signer}
  def sign_many(payload, signers)
      when is_binary(payload) and is_list(signers) and signers != [] do
    pae = pae(payload)

    with {:ok, signatures} <- sign_all(signers, pae, []) do
      {:ok,
       %{
         "payload" => encode_base64url(payload),
         "payloadType" => @payload_type,
         "signatures" => signatures
       }}
    end
  end

  def sign_many(_, _), do: {:error, :invalid_envelope}

  @doc """
  Append a signature to an existing envelope over its identical PAE bytes.

  DSSE cosigning (SP.05): the `payload` and existing signatures are unchanged and
  the appended signature covers the same PAE bytes. A key id already present in
  the envelope (or produced by `signer`) fails `:duplicate_keyid`; a signer that
  cannot produce an Ed25519 signature fails `:invalid_signer`.
  """
  @spec add_signature(envelope() | term(), signer(), keyword()) ::
          {:ok, envelope()}
          | {:error,
             :invalid_envelope
             | :invalid_payload_type
             | :invalid_base64
             | :duplicate_keyid
             | :invalid_signer}
  def add_signature(envelope, signer, opts \\ [])

  def add_signature(envelope, signer, opts) when is_map(envelope) do
    keyid = Keyword.get(opts, :keyid)

    with {:ok, fields} <- envelope_fields(envelope),
         :ok <- require_payload_type(fields.payload_type),
         {:ok, existing} <- signature_fields(fields.signatures),
         :ok <- reject_duplicate_keyids(existing),
         {:ok, payload} <- decode_base64(fields.payload),
         {:ok, [entry]} <- sign_all([{signer, keyid}], pae(fields.payload_type, payload), []),
         :ok <- reject_present_keyid(existing, entry) do
      {:ok, Map.put(envelope, "signatures", Enum.concat(fields.signatures, [entry]))}
    end
  end

  def add_signature(_, _, _), do: {:error, :invalid_envelope}

  @doc """
  Verify a DSSE envelope and return the signed payload bytes.

  `public_keys` maps key ids to raw 32-byte Ed25519 public keys or base64 /
  base64url encoded public keys. Unresolved key ids are tolerated as witness
  signatures, but at least one signature must resolve.
  """
  @spec verify(envelope() | term(), map()) :: {:ok, binary()} | {:error, verify_error()}
  def verify(envelope, public_keys) when is_map(public_keys) do
    with {:ok, fields} <- envelope_fields(envelope),
         :ok <- require_payload_type(fields.payload_type),
         {:ok, signatures} <- signature_fields(fields.signatures),
         :ok <- reject_duplicate_keyids(signatures),
         {:ok, payload} <- decode_base64(fields.payload) do
      verify_signatures(signatures, public_keys, pae(fields.payload_type, payload), payload)
    end
  end

  def verify(_, _), do: {:error, :missing_trust_bundle}

  @doc """
  Derive the SigilGuard-local key id for a raw Ed25519 public key.
  """
  @spec keyid(binary()) :: String.t()
  def keyid(public_key)
      when is_binary(public_key) and byte_size(public_key) == @ed25519_public_key_bytes do
    "sha256:" <> Base.encode16(:crypto.hash(:sha256, public_key), case: :lower)
  end

  defp sign_all([], _, signatures), do: {:ok, Enum.reverse(signatures)}

  defp sign_all([signer | rest], pae, signatures) do
    with {:ok, module, configured_keyid} <- normalize_signer(signer),
         {:ok, public_key} <- signer_public_key(module),
         {:ok, keyid} <- signer_keyid(configured_keyid, public_key),
         {:ok, signature} <- signer_signature(module, pae) do
      sign_all(rest, pae, [%{"keyid" => keyid, "sig" => encode_base64url(signature)} | signatures])
    end
  end

  defp normalize_signer({module, keyid})
       when is_atom(module) and (is_binary(keyid) or is_nil(keyid)) do
    {:ok, module, keyid}
  end

  defp normalize_signer(module) when is_atom(module), do: {:ok, module, nil}
  defp normalize_signer(_), do: {:error, :invalid_signer}

  defp signer_public_key(module) do
    if function_exported?(module, :public_key, 0) do
      case module.public_key() do
        public_key
        when is_binary(public_key) and byte_size(public_key) == @ed25519_public_key_bytes ->
          {:ok, public_key}

        _ ->
          {:error, :invalid_signer}
      end
    else
      {:error, :invalid_signer}
    end
  rescue
    _ -> {:error, :invalid_signer}
  end

  defp signer_keyid(nil, public_key), do: {:ok, keyid(public_key)}
  defp signer_keyid(keyid, _) when is_binary(keyid) and keyid != "", do: {:ok, keyid}
  defp signer_keyid(_, _), do: {:error, :invalid_signer}

  defp signer_signature(module, pae) do
    if function_exported?(module, :sign, 1) do
      case module.sign(pae) do
        signature
        when is_binary(signature) and byte_size(signature) == @ed25519_signature_bytes ->
          {:ok, signature}

        _ ->
          {:error, :invalid_signer}
      end
    else
      {:error, :invalid_signer}
    end
  rescue
    _ -> {:error, :invalid_signer}
  end

  defp envelope_fields(%{} = envelope) do
    payload = field(envelope, "payload")
    payload_type = field(envelope, "payloadType")
    signatures = field(envelope, "signatures")

    valid_envelope? =
      is_binary(payload) and is_binary(payload_type) and is_list(signatures) and signatures != []

    if valid_envelope? do
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

  defp require_payload_type(@payload_type), do: :ok
  defp require_payload_type(_), do: {:error, :invalid_payload_type}

  defp signature_fields(signatures) do
    parsed =
      Enum.reduce_while(signatures, {:ok, []}, fn signature, {:ok, parsed} ->
        case signature_field(signature) do
          {:ok, fields} -> {:cont, {:ok, [fields | parsed]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)

    case parsed do
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

  defp reject_present_keyid(existing, entry) do
    if Enum.any?(existing, &(&1.keyid == entry["keyid"])),
      do: {:error, :duplicate_keyid},
      else: :ok
  end

  defp verify_signatures(signatures, public_keys, pae, payload) do
    result =
      Enum.reduce_while(signatures, {:ok, 0}, &verify_signature(&1, &2, public_keys, pae))

    case result do
      {:ok, resolved} when resolved > 0 -> {:ok, payload}
      {:ok, 0} -> {:error, :unknown_key_id}
      {:error, reason} -> {:error, reason}
    end
  end

  defp verify_signature(signature, {:ok, resolved}, public_keys, pae) do
    case Map.fetch(public_keys, signature.keyid) do
      {:ok, encoded_key} ->
        with {:ok, public_key} <- decode_public_key(encoded_key),
             {:ok, decoded_signature} <- decode_base64(signature.sig),
             :ok <- verify_ed25519(pae, decoded_signature, public_key) do
          {:cont, {:ok, resolved + 1}}
        else
          {:error, reason} -> {:halt, {:error, reason}}
        end

      :error ->
        {:cont, {:ok, resolved}}
    end
  end

  defp decode_public_key(public_key)
       when is_binary(public_key) and byte_size(public_key) == @ed25519_public_key_bytes do
    {:ok, public_key}
  end

  defp decode_public_key(encoded_key) when is_binary(encoded_key) do
    case decode_base64(encoded_key) do
      {:ok, public_key} when byte_size(public_key) == @ed25519_public_key_bytes ->
        {:ok, public_key}

      {:ok, _} ->
        {:error, :invalid_signature}

      {:error, :invalid_base64} ->
        {:error, :invalid_signature}
    end
  end

  defp decode_public_key(_), do: {:error, :invalid_signature}

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

  defp encode_base64url(value), do: Base.url_encode64(value, padding: false)

  defp decode_base64(value) when is_binary(value) do
    with :error <- Base.url_decode64(value, padding: false),
         :error <- Base.url_decode64(value, padding: true),
         :error <- Base.decode64(value, padding: false),
         :error <- Base.decode64(value, padding: true) do
      {:error, :invalid_base64}
    end
  end

  defp decode_base64(_), do: {:error, :invalid_base64}
end
