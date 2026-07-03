defmodule SigilGuard.TrustBundle.Schema do
  @moduledoc """
  Schema validation for SP.02 trust-bundle documents.

  This module validates decoded bundle and root-rotation documents. It does
  not perform signature, threshold, revocation, expiry, rollback-cache, or
  rotation-chain verification; those checks belong to the verification
  pipeline.
  """

  alias SigilGuard.Attestation.Envelope

  @bundle_profile "sigil_guard_trust_bundle/v1"
  @bundle_profile_stem "sigil_guard_trust_bundle/"
  @rotation_profile "sigil_guard_root_rotation/v1"
  @rotation_profile_stem "sigil_guard_root_rotation/"
  @positive_integer_string ~r/^[1-9][0-9]*$/
  @iso8601_utc_ms ~r/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
  @keyid_regex ~r/^sha256:[0-9a-f]{64}$/
  @bundle_fields ~w(
                   profile
                   bundle_id
                   sequence
                   issued_at
                   expires_at
                   roles
                   keys
                   tools
                   policies
                   patterns
                   identity_issuers
                   revocations
                   rollback_floor
                   rotation_chain
                   provenance
                 )
  @rotation_fields ~w(
                     profile
                     bundle_id
                     root_version
                     roles
                     keys
                     rollback_floor
                     issued_at
                   )
  @root_fields ~w(keyids threshold version expires_at)
  @delegate_fields ~w(name keyids threshold expires_at)
  @key_fields ~w(alg public_key)
  @revocation_fields ~w(kind id revoked_at)
  @revocation_kinds ~w(key bundle manifest actor)

  @type document_type :: :bundle | :rotation
  @type schema_error :: :invalid_bundle_format | :unsupported_profile_version | :unknown_role

  @doc """
  Validate a decoded bundle or root-rotation document.
  """
  @spec validate(map()) :: {:ok, document_type(), map()} | {:error, schema_error()}
  def validate(%{} = document) do
    case Map.get(document, "profile") do
      @bundle_profile -> validate_bundle(document)
      @rotation_profile -> validate_rotation(document)
      profile when is_binary(profile) -> unsupported_or_invalid_profile(profile)
      _ -> {:error, :invalid_bundle_format}
    end
  end

  def validate(_), do: {:error, :invalid_bundle_format}

  @doc """
  Validate a decoded trust-bundle document.
  """
  @spec validate_bundle(map()) :: {:ok, :bundle, map()} | {:error, schema_error()}
  def validate_bundle(%{} = document) do
    with :ok <- exact_keys(document, @bundle_fields),
         :ok <- required_binary(document, "bundle_id"),
         {:ok, sequence} <- positive_integer_field(document, "sequence"),
         {:ok, rollback_floor} <- positive_integer_field(document, "rollback_floor"),
         :ok <- rollback_floor_not_above_sequence(rollback_floor, sequence),
         :ok <- validate_lifetime(document),
         {:ok, keys} <- validate_keys(Map.get(document, "keys")),
         :ok <- validate_roles(Map.get(document, "roles"), keys, require_bundle?: true),
         :ok <- optional_list(document, "tools"),
         :ok <- optional_list(document, "policies"),
         :ok <- optional_list(document, "patterns"),
         :ok <- optional_list(document, "identity_issuers"),
         :ok <- optional_list(document, "rotation_chain"),
         :ok <- optional_map(document, "provenance"),
         :ok <- validate_revocations(Map.get(document, "revocations", [])) do
      {:ok, :bundle, document}
    end
  end

  def validate_bundle(_), do: {:error, :invalid_bundle_format}

  @doc """
  Validate a decoded root-rotation document.
  """
  @spec validate_rotation(map()) :: {:ok, :rotation, map()} | {:error, schema_error()}
  def validate_rotation(%{} = document) do
    with :ok <- exact_keys(document, @rotation_fields),
         :ok <- required_binary(document, "bundle_id"),
         {:ok, root_version} <- positive_integer_field(document, "root_version"),
         {:ok, _} <- positive_integer_field(document, "rollback_floor"),
         :ok <- timestamp_field(document, "issued_at"),
         {:ok, keys} <- validate_keys(Map.get(document, "keys")),
         :ok <- validate_rotation_roles(Map.get(document, "roles"), keys, root_version) do
      {:ok, :rotation, document}
    end
  end

  def validate_rotation(_), do: {:error, :invalid_bundle_format}

  defp unsupported_or_invalid_profile(profile) do
    if String.starts_with?(profile, @bundle_profile_stem) or
         String.starts_with?(profile, @rotation_profile_stem) do
      {:error, :unsupported_profile_version}
    else
      {:error, :invalid_bundle_format}
    end
  end

  defp exact_keys(map, allowed) when is_map(map) do
    keys = Map.keys(map)

    if Enum.all?(keys, &is_binary/1) and Enum.all?(keys, &(&1 in allowed)) do
      :ok
    else
      {:error, :invalid_bundle_format}
    end
  end

  defp required_binary(map, key) do
    case Map.get(map, key) do
      value when is_binary(value) and value != "" -> :ok
      _ -> {:error, :invalid_bundle_format}
    end
  end

  defp positive_integer_field(map, key) do
    case Map.get(map, key) do
      value when is_binary(value) ->
        if Regex.match?(@positive_integer_string, value) do
          {:ok, String.to_integer(value)}
        else
          {:error, :invalid_bundle_format}
        end

      _ ->
        {:error, :invalid_bundle_format}
    end
  end

  defp rollback_floor_not_above_sequence(rollback_floor, sequence) do
    if rollback_floor <= sequence, do: :ok, else: {:error, :invalid_bundle_format}
  end

  defp validate_lifetime(document) do
    with {:ok, issued_at} <- parse_timestamp(Map.get(document, "issued_at")),
         {:ok, expires_at} <- parse_timestamp(Map.get(document, "expires_at")) do
      if DateTime.before?(issued_at, expires_at), do: :ok, else: {:error, :invalid_bundle_format}
    end
  end

  defp timestamp_field(map, key) do
    case parse_timestamp(Map.get(map, key)) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp parse_timestamp(value) when is_binary(value) do
    with true <- Regex.match?(@iso8601_utc_ms, value),
         {:ok, datetime, 0} <- DateTime.from_iso8601(value) do
      {:ok, datetime}
    else
      _ -> {:error, :invalid_bundle_format}
    end
  end

  defp parse_timestamp(_), do: {:error, :invalid_bundle_format}

  defp validate_keys(keys) when is_map(keys) and map_size(keys) > 0 do
    keys
    |> Enum.reduce_while({:ok, MapSet.new()}, fn {keyid, descriptor}, {:ok, keyids} ->
      case validate_key(keyid, descriptor) do
        :ok -> {:cont, {:ok, MapSet.put(keyids, keyid)}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp validate_keys(_), do: {:error, :invalid_bundle_format}

  defp validate_key(keyid, %{} = descriptor) when is_binary(keyid) do
    with true <- Regex.match?(@keyid_regex, keyid),
         :ok <- exact_keys(descriptor, @key_fields),
         "ed25519" <- Map.get(descriptor, "alg"),
         {:ok, public_key} <- decode_public_key(Map.get(descriptor, "public_key")),
         true <- Envelope.keyid(public_key) == keyid do
      :ok
    else
      _ -> {:error, :invalid_bundle_format}
    end
  end

  defp validate_key(_, _), do: {:error, :invalid_bundle_format}

  defp decode_public_key(value) when is_binary(value) do
    case Base.url_decode64(value, padding: false) do
      {:ok, public_key} when byte_size(public_key) == 32 -> {:ok, public_key}
      _ -> {:error, :invalid_bundle_format}
    end
  end

  defp decode_public_key(_), do: {:error, :invalid_bundle_format}

  defp validate_roles(%{"root" => root, "delegates" => delegates} = roles, keys, opts)
       when map_size(roles) == 2 and is_list(delegates) do
    with :ok <- validate_root(root, keys),
         :ok <- validate_delegates(delegates, keys) do
      maybe_require_bundle_delegate(delegates, opts)
    end
  end

  defp validate_roles(_, _, _), do: {:error, :invalid_bundle_format}

  defp validate_rotation_roles(%{"root" => root} = roles, keys, root_version)
       when map_size(roles) == 1 do
    with :ok <- validate_root(root, keys),
         ^root_version <- role_version(root) do
      :ok
    else
      _ -> {:error, :invalid_bundle_format}
    end
  end

  defp validate_rotation_roles(_, _, _), do: {:error, :invalid_bundle_format}

  defp validate_root(%{} = root, keys) do
    with :ok <- exact_keys(root, @root_fields),
         {:ok, _} <- positive_integer_field(root, "version"),
         :ok <- timestamp_field(root, "expires_at") do
      validate_role_keyids(Map.get(root, "keyids"), Map.get(root, "threshold"), keys)
    end
  end

  defp validate_root(_, _), do: {:error, :invalid_bundle_format}

  defp role_version(root) do
    case positive_integer_field(root, "version") do
      {:ok, version} -> version
      {:error, _} -> :error
    end
  end

  defp validate_delegates(delegates, keys) when delegates != [] do
    case Enum.reduce_while(delegates, {:ok, MapSet.new()}, fn delegate, {:ok, names} ->
           reduce_delegate(delegate, keys, names)
         end) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp validate_delegates(_, _), do: {:error, :invalid_bundle_format}

  defp reduce_delegate(delegate, keys, names) do
    case validate_delegate(delegate, keys, names) do
      {:ok, name} -> {:cont, {:ok, MapSet.put(names, name)}}
      {:error, reason} -> {:halt, {:error, reason}}
    end
  end

  defp validate_delegate(%{} = delegate, keys, names) do
    with :ok <- exact_keys(delegate, @delegate_fields),
         name when is_binary(name) and name != "" <- Map.get(delegate, "name"),
         false <- MapSet.member?(names, name),
         :ok <- timestamp_field(delegate, "expires_at"),
         :ok <-
           validate_role_keyids(Map.get(delegate, "keyids"), Map.get(delegate, "threshold"), keys) do
      {:ok, name}
    else
      _ -> {:error, :invalid_bundle_format}
    end
  end

  defp validate_delegate(_, _, _), do: {:error, :invalid_bundle_format}

  defp validate_role_keyids(keyids, threshold, keys)
       when is_list(keyids) and is_integer(threshold) and keyids != [] do
    cond do
      not Enum.all?(keyids, &is_binary/1) -> {:error, :invalid_bundle_format}
      Enum.uniq(keyids) != keyids -> {:error, :invalid_bundle_format}
      threshold < 1 or threshold > length(keyids) -> {:error, :invalid_bundle_format}
      not Enum.all?(keyids, &MapSet.member?(keys, &1)) -> {:error, :invalid_bundle_format}
      true -> :ok
    end
  end

  defp validate_role_keyids(_, _, _), do: {:error, :invalid_bundle_format}

  defp maybe_require_bundle_delegate(delegates, opts) do
    if Keyword.get(opts, :require_bundle?, false) and
         not Enum.any?(delegates, &(Map.get(&1, "name") == "bundle")) do
      {:error, :unknown_role}
    else
      :ok
    end
  end

  defp optional_list(document, key) do
    case Map.fetch(document, key) do
      {:ok, value} when is_list(value) -> :ok
      {:ok, _} -> {:error, :invalid_bundle_format}
      :error -> :ok
    end
  end

  defp optional_map(document, key) do
    case Map.fetch(document, key) do
      {:ok, value} when is_map(value) -> :ok
      {:ok, _} -> {:error, :invalid_bundle_format}
      :error -> :ok
    end
  end

  defp validate_revocations(revocations) when is_list(revocations) do
    Enum.reduce_while(revocations, :ok, fn revocation, :ok ->
      case validate_revocation(revocation) do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp validate_revocations(_), do: {:error, :invalid_bundle_format}

  defp validate_revocation(%{} = revocation) do
    with :ok <- exact_keys(revocation, @revocation_fields),
         kind when kind in @revocation_kinds <- Map.get(revocation, "kind"),
         :ok <- required_binary(revocation, "id"),
         :ok <- timestamp_field(revocation, "revoked_at") do
      :ok
    else
      _ -> {:error, :invalid_bundle_format}
    end
  end

  defp validate_revocation(_), do: {:error, :invalid_bundle_format}
end
