defmodule SigilGuard.CapabilityManifest do
  @moduledoc """
  Canonical capability-manifest form for SP.03 tool verification.

  A capability manifest binds a tool's observed MCP definition and security
  properties to a deterministic digest. The carried form includes human-facing
  text and schemas; the digest preimage replaces those larger fields with
  lower-case SHA-256 values over their normative byte representation.
  """

  alias SigilGuard.Attestation.Digest
  alias SigilGuard.Canonical.JCS

  @manifest_format "sigil_guard_capability_manifest/v1"
  @sha256_regex ~r/^[0-9a-f]{64}$/
  @keyid_regex ~r/^sha256:[0-9a-f]{64}$/
  @timestamp_regex ~r/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/

  @string_fields ~w(
    description
    expires_at
    input_sensitivity
    issuer_keyid
    manifest_format
    name
    network_access
    output_sensitivity
    reversibility
    server
    version
  )
  @digest_fields ~w(
    annotations_sha256
    description_sha256
    input_schema_sha256
    output_schema_sha256
  )
  @list_fields ~w(
    allowed_sink_zones
    allowed_source_zones
    audience
    scopes
    side_effects
    suspicious_params
  )
  @schema_fields ~w(annotations input_schema output_schema)
  @preimage_string_fields @string_fields -- ["description"]
  @allowed_fields MapSet.new(
                    List.flatten([
                      @string_fields,
                      @digest_fields,
                      @list_fields,
                      @schema_fields,
                      ["sandbox"]
                    ])
                  )
  @preimage_fields List.flatten([["sandbox"], @preimage_string_fields, @list_fields])
  @required_fields ~w(
    description
    expires_at
    input_schema
    input_sensitivity
    issuer_keyid
    manifest_format
    name
    network_access
    output_sensitivity
    reversibility
    sandbox
    server
    side_effects
    suspicious_params
    version
  )
  @input_sensitivity ~w(public internal private)
  @output_sensitivity ~w(public internal private)
  @network_access ~w(none outbound bidirectional)
  @reversibility ~w(reversible irreversible)
  @side_effects ~w(none read write delete execute privileged)
  @isolation_levels ~w(container vm remote_attested)
  @suspicious_param_indicators ~w(
    access_key
    api_key
    apikey
    authorization
    bearer
    cookie
    credential
    passwd
    password
    private_key
    secret
    session_id
    token
  )

  @type error ::
          :invalid_manifest
          | :suspicious_required_param
          | :unsupported_number_range
          | :manifest_digest_mismatch
          | :schema_digest_mismatch

  @type t :: %__MODULE__{
          allowed_sink_zones: [String.t()] | nil,
          allowed_source_zones: [String.t()] | nil,
          annotations: map() | nil,
          annotations_sha256: String.t() | nil,
          audience: [String.t()] | nil,
          description: String.t(),
          description_sha256: String.t(),
          expires_at: String.t(),
          input_schema: map(),
          input_schema_sha256: String.t(),
          input_sensitivity: String.t(),
          issuer_keyid: String.t(),
          manifest_format: String.t(),
          name: String.t(),
          network_access: String.t(),
          output_schema: map() | nil,
          output_schema_sha256: String.t() | nil,
          output_sensitivity: String.t(),
          reversibility: String.t(),
          sandbox: map(),
          scopes: [String.t()] | nil,
          server: String.t(),
          side_effects: [String.t()],
          suspicious_params: [String.t()],
          version: String.t(),
          preimage: map(),
          digest: String.t()
        }

  defstruct allowed_sink_zones: nil,
            allowed_source_zones: nil,
            annotations: nil,
            annotations_sha256: nil,
            audience: nil,
            description: nil,
            description_sha256: nil,
            expires_at: nil,
            input_schema: nil,
            input_schema_sha256: nil,
            input_sensitivity: nil,
            issuer_keyid: nil,
            manifest_format: @manifest_format,
            name: nil,
            network_access: nil,
            output_schema: nil,
            output_schema_sha256: nil,
            output_sensitivity: nil,
            reversibility: nil,
            sandbox: nil,
            scopes: nil,
            server: nil,
            side_effects: [],
            suspicious_params: [],
            version: nil,
            preimage: %{},
            digest: nil

  @doc """
  Validate and normalize a carried capability manifest.
  """
  @spec new(map()) ::
          {:ok, t()}
          | {:error, :invalid_manifest | :suspicious_required_param | :unsupported_number_range}
  def new(manifest) when is_map(manifest) do
    with {:ok, manifest} <- normalize_manifest(manifest),
         :ok <- closed_fields(manifest),
         :ok <- required_fields(manifest),
         :ok <- validate_strings(manifest),
         :ok <- validate_enums(manifest),
         :ok <- validate_lists(manifest),
         :ok <- validate_sandbox(manifest),
         {:ok, computed} <- computed_fields(manifest),
         :ok <- validate_carried_digests(manifest, computed),
         :ok <- validate_suspicious_params(manifest, computed),
         preimage <- preimage(manifest, computed),
         {:ok, digest} <- digest_preimage(preimage) do
      {:ok, struct!(__MODULE__, struct_fields(manifest, computed, preimage, digest))}
    end
  end

  def new(_), do: {:error, :invalid_manifest}

  @doc """
  Compute the SP.03 manifest digest.
  """
  @spec digest(t() | map()) ::
          {:ok, String.t()} | {:error, :invalid_manifest | :unsupported_number_range}
  def digest(%__MODULE__{digest: digest}) when is_binary(digest), do: {:ok, digest}

  def digest(%__MODULE__{preimage: preimage}) when is_map(preimage), do: digest_preimage(preimage)

  def digest(manifest) when is_map(manifest) do
    case new(manifest) do
      {:ok, %__MODULE__{digest: digest}} -> {:ok, digest}
      {:error, :suspicious_required_param} -> {:error, :invalid_manifest}
      {:error, reason} -> {:error, reason}
    end
  end

  def digest(_), do: {:error, :invalid_manifest}

  @doc """
  Compare an observed manifest against a previously pinned manifest.
  """
  @spec verify(t() | map(), map()) ::
          :ok
          | {:error,
             :manifest_digest_mismatch
             | :schema_digest_mismatch
             | :suspicious_required_param
             | :invalid_manifest}
  def verify(pinned, observed) do
    with {:ok, pinned} <- manifest_struct(pinned),
         {:ok, observed} <- new(observed),
         :ok <- matching_schema_digests(pinned, observed),
         :ok <- matching_digest(pinned, observed) do
      :ok
    else
      {:error, :unsupported_number_range} -> {:error, :invalid_manifest}
      {:error, reason} -> {:error, reason}
    end
  end

  defp manifest_struct(%__MODULE__{} = manifest), do: {:ok, manifest}
  defp manifest_struct(manifest) when is_map(manifest), do: new(manifest)
  defp manifest_struct(_), do: {:error, :invalid_manifest}

  defp normalize_manifest(manifest) do
    case Digest.normalize(manifest) do
      {:ok, normalized} when is_map(normalized) -> {:ok, normalized}
      {:ok, _} -> {:error, :invalid_manifest}
      {:error, _} -> {:error, :invalid_manifest}
    end
  end

  defp closed_fields(manifest) do
    valid? =
      manifest
      |> Map.keys()
      |> Enum.all?(&MapSet.member?(@allowed_fields, &1))

    if valid? do
      :ok
    else
      {:error, :invalid_manifest}
    end
  end

  defp required_fields(manifest) do
    if Enum.all?(@required_fields, &Map.has_key?(manifest, &1)) do
      :ok
    else
      {:error, :invalid_manifest}
    end
  end

  defp validate_strings(manifest) do
    checks = [
      string_field(manifest, "description"),
      string_field(manifest, "name"),
      string_field(manifest, "server"),
      string_field(manifest, "version"),
      exact_field(manifest, "manifest_format", @manifest_format),
      regex_field(manifest, "issuer_keyid", @keyid_regex),
      regex_field(manifest, "expires_at", @timestamp_regex)
    ]

    if Enum.all?(checks, &(&1 == :ok)), do: :ok, else: {:error, :invalid_manifest}
  end

  defp validate_enums(manifest) do
    checks = [
      enum_field(manifest, "input_sensitivity", @input_sensitivity),
      enum_field(manifest, "output_sensitivity", @output_sensitivity),
      enum_field(manifest, "network_access", @network_access),
      enum_field(manifest, "reversibility", @reversibility)
    ]

    if Enum.all?(checks, &(&1 == :ok)), do: :ok, else: {:error, :invalid_manifest}
  end

  defp validate_lists(manifest) do
    optional =
      ["allowed_sink_zones", "allowed_source_zones", "audience", "scopes"]
      |> Enum.map(&optional_sorted_string_list(manifest, &1))

    checks =
      optional ++
        [
          required_sorted_string_list(manifest, "suspicious_params"),
          side_effects(manifest)
        ]

    if Enum.all?(checks, &(&1 == :ok)), do: :ok, else: {:error, :invalid_manifest}
  end

  defp validate_sandbox(
         %{"sandbox" => %{"required" => true, "min_isolation" => level}} = manifest
       ) do
    sandbox = Map.fetch!(manifest, "sandbox")

    if Map.keys(sandbox) |> Enum.sort() == ["min_isolation", "required"] and
         level in @isolation_levels do
      :ok
    else
      {:error, :invalid_manifest}
    end
  end

  defp validate_sandbox(%{"sandbox" => %{"required" => false}} = manifest) do
    if Map.keys(Map.fetch!(manifest, "sandbox")) == ["required"] do
      :ok
    else
      {:error, :invalid_manifest}
    end
  end

  defp validate_sandbox(_), do: {:error, :invalid_manifest}

  defp computed_fields(manifest) do
    with {:ok, description_sha256} <- sha256_bytes(Map.fetch!(manifest, "description")),
         {:ok, input_schema_sha256} <- sha256_jcs(Map.fetch!(manifest, "input_schema")),
         {:ok, annotations_sha256} <- optional_sha256_jcs(manifest, "annotations"),
         {:ok, output_schema_sha256} <- optional_sha256_jcs(manifest, "output_schema"),
         suspicious_params <- suspicious_params(Map.fetch!(manifest, "input_schema")) do
      {:ok,
       %{
         "annotations_sha256" => annotations_sha256,
         "description_sha256" => description_sha256,
         "input_schema_sha256" => input_schema_sha256,
         "output_schema_sha256" => output_schema_sha256,
         "suspicious_params" => suspicious_params
       }}
    end
  end

  defp validate_carried_digests(manifest, computed) do
    checks =
      @digest_fields
      |> Enum.map(fn field ->
        case {Map.fetch(manifest, field), Map.fetch!(computed, field)} do
          {:error, _} ->
            :ok

          {{:ok, digest}, digest} when is_binary(digest) ->
            regex_field(manifest, field, @sha256_regex)

          _ ->
            {:error, :invalid_manifest}
        end
      end)

    if Enum.all?(checks, &(&1 == :ok)), do: :ok, else: {:error, :invalid_manifest}
  end

  defp validate_suspicious_params(manifest, computed) do
    if Map.fetch!(manifest, "suspicious_params") == Map.fetch!(computed, "suspicious_params") do
      :ok
    else
      {:error, :suspicious_required_param}
    end
  end

  defp preimage(manifest, computed) do
    manifest
    |> Map.take(@preimage_fields)
    |> Map.put("description_sha256", Map.fetch!(computed, "description_sha256"))
    |> Map.put("input_schema_sha256", Map.fetch!(computed, "input_schema_sha256"))
    |> maybe_put("annotations_sha256", Map.fetch!(computed, "annotations_sha256"))
    |> maybe_put("output_schema_sha256", Map.fetch!(computed, "output_schema_sha256"))
  end

  defp struct_fields(manifest, computed, preimage, digest) do
    %{
      allowed_sink_zones: Map.get(manifest, "allowed_sink_zones"),
      allowed_source_zones: Map.get(manifest, "allowed_source_zones"),
      annotations: Map.get(manifest, "annotations"),
      annotations_sha256: Map.fetch!(computed, "annotations_sha256"),
      audience: Map.get(manifest, "audience"),
      description: Map.fetch!(manifest, "description"),
      description_sha256: Map.fetch!(computed, "description_sha256"),
      expires_at: Map.fetch!(manifest, "expires_at"),
      input_schema: Map.fetch!(manifest, "input_schema"),
      input_schema_sha256: Map.fetch!(computed, "input_schema_sha256"),
      input_sensitivity: Map.fetch!(manifest, "input_sensitivity"),
      issuer_keyid: Map.fetch!(manifest, "issuer_keyid"),
      manifest_format: Map.fetch!(manifest, "manifest_format"),
      name: Map.fetch!(manifest, "name"),
      network_access: Map.fetch!(manifest, "network_access"),
      output_schema: Map.get(manifest, "output_schema"),
      output_schema_sha256: Map.fetch!(computed, "output_schema_sha256"),
      output_sensitivity: Map.fetch!(manifest, "output_sensitivity"),
      reversibility: Map.fetch!(manifest, "reversibility"),
      sandbox: Map.fetch!(manifest, "sandbox"),
      scopes: Map.get(manifest, "scopes"),
      server: Map.fetch!(manifest, "server"),
      side_effects: Map.fetch!(manifest, "side_effects"),
      suspicious_params: Map.fetch!(manifest, "suspicious_params"),
      version: Map.fetch!(manifest, "version"),
      preimage: preimage,
      digest: digest
    }
  end

  defp matching_schema_digests(pinned, observed) do
    if pinned.input_schema_sha256 == observed.input_schema_sha256 and
         pinned.output_schema_sha256 == observed.output_schema_sha256 do
      :ok
    else
      {:error, :schema_digest_mismatch}
    end
  end

  defp matching_digest(pinned, observed) do
    if pinned.digest == observed.digest do
      :ok
    else
      {:error, :manifest_digest_mismatch}
    end
  end

  defp digest_preimage(preimage) do
    case JCS.encode(preimage) do
      {:ok, canonical} -> {:ok, sha256_hex(canonical)}
      {:error, :unsupported_number_range} -> {:error, :unsupported_number_range}
      {:error, _} -> {:error, :invalid_manifest}
    end
  end

  defp optional_sha256_jcs(manifest, field) do
    case Map.fetch(manifest, field) do
      {:ok, value} -> sha256_jcs(value)
      :error -> {:ok, nil}
    end
  end

  defp sha256_jcs(value) when is_map(value) do
    case JCS.encode(value) do
      {:ok, canonical} -> {:ok, sha256_hex(canonical)}
      {:error, :unsupported_number_range} -> {:error, :unsupported_number_range}
      {:error, _} -> {:error, :invalid_manifest}
    end
  end

  defp sha256_jcs(_), do: {:error, :invalid_manifest}

  defp sha256_bytes(value) when is_binary(value) do
    if String.valid?(value), do: {:ok, sha256_hex(value)}, else: {:error, :invalid_manifest}
  end

  defp sha256_bytes(_), do: {:error, :invalid_manifest}

  defp sha256_hex(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

  defp suspicious_params(schema) do
    schema
    |> required_names([])
    |> Enum.filter(&suspicious_name?/1)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp required_names(%{"required" => required} = schema, acc) when is_list(required) do
    schema
    |> Map.delete("required")
    |> required_names(acc ++ Enum.filter(required, &is_binary/1))
  end

  defp required_names(%{} = schema, acc) do
    Enum.reduce(schema, acc, fn {_, value}, names -> required_names(value, names) end)
  end

  defp required_names(list, acc) when is_list(list) do
    Enum.reduce(list, acc, &required_names/2)
  end

  defp required_names(_, acc), do: acc

  defp suspicious_name?(name) do
    normalized =
      name
      |> String.downcase()
      |> String.replace("-", "_")

    Enum.any?(@suspicious_param_indicators, &String.contains?(normalized, &1))
  end

  defp optional_sorted_string_list(manifest, field) do
    case Map.fetch(manifest, field) do
      {:ok, list} -> sorted_string_list(list)
      :error -> :ok
    end
  end

  defp required_sorted_string_list(manifest, field) do
    case Map.fetch(manifest, field) do
      {:ok, list} -> sorted_string_list(list)
      :error -> {:error, :invalid_manifest}
    end
  end

  defp side_effects(manifest) do
    with {:ok, effects} <- Map.fetch(manifest, "side_effects"),
         :ok <- sorted_string_list(effects),
         true <- effects != [],
         true <- Enum.all?(effects, &(&1 in @side_effects)),
         true <- "none" not in effects or effects == ["none"] do
      :ok
    else
      _ -> {:error, :invalid_manifest}
    end
  end

  defp sorted_string_list(list) when is_list(list) do
    cond do
      not Enum.all?(list, &is_binary/1) -> {:error, :invalid_manifest}
      list != Enum.sort(list) -> {:error, :invalid_manifest}
      list != Enum.uniq(list) -> {:error, :invalid_manifest}
      true -> :ok
    end
  end

  defp sorted_string_list(_), do: {:error, :invalid_manifest}

  defp string_field(manifest, field) do
    case Map.fetch(manifest, field) do
      {:ok, value} when is_binary(value) and value != "" -> :ok
      _ -> {:error, :invalid_manifest}
    end
  end

  defp exact_field(manifest, field, expected) do
    if Map.get(manifest, field) == expected, do: :ok, else: {:error, :invalid_manifest}
  end

  defp enum_field(manifest, field, allowed) do
    if Map.get(manifest, field) in allowed, do: :ok, else: {:error, :invalid_manifest}
  end

  defp regex_field(manifest, field, regex) do
    value = Map.get(manifest, field)

    if is_binary(value) and Regex.match?(regex, value) do
      :ok
    else
      {:error, :invalid_manifest}
    end
  end

  defp maybe_put(map, _, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
