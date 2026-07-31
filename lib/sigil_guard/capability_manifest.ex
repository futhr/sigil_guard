defmodule SigilGuard.CapabilityManifest do
  @moduledoc """
  Pins an MCP tool definition and its security properties to one digest.

  A capability manifest is the trust boundary between a tool discovered from
  an MCP server and the tool a host previously reviewed. The carried form keeps
  the description, schemas, display metadata, and security declarations needed
  by callers. Its compact preimage replaces large values with lowercase
  SHA-256 digests over their canonical representation.

  Manifest v2 also binds MCP `2026-07-28` display fields and MCP Apps metadata:
  `title`, `icons`, a `ui://` resource, caller visibility, and every
  `x-mcp-header` annotation in `input_schema`.

  Header annotations are accepted only on `boolean`, `integer`, or `string`
  properties statically reachable through `properties`-only schema paths.
  Header names use HTTP token syntax and are unique without regard to case.
  Parameters whose names resemble credentials or private data are rejected.
  The host transport still owns value encoding, the safe-integer check for
  actual integer arguments, and header/body mismatch handling.

  SigilGuard binds complete JSON Schema values but does not implement a JSON
  Schema evaluator or dereference `$ref` URIs. The host MCP adapter must
  validate the declared schema dialect and reject unresolved external
  references before constructing a manifest. Icon consumers must also enforce
  same-origin fetching, credential-free requests, redirect restrictions,
  byte and dimension limits, content sniffing, and safe rendering.
  """
  @moduledoc since: "1.0.0"

  alias SigilGuard.Attestation.Digest
  alias SigilGuard.Canonical.JCS

  @manifest_format "sigil_guard_capability_manifest/v2"
  @sha256_regex ~r/\A[0-9a-f]{64}\z/
  @keyid_regex ~r/\Asha256:[0-9a-f]{64}\z/
  @timestamp_regex ~r/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\z/

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
    icons_sha256
    input_schema_sha256
    output_schema_sha256
    title_sha256
    ui_sha256
  )
  @list_fields ~w(
    allowed_sink_zones
    allowed_source_zones
    audience
    scopes
    side_effects
    suspicious_params
  )
  @schema_fields ~w(annotations input_schema output_schema ui)
  @optional_display_fields ~w(icons title)
  @preimage_string_fields @string_fields -- ["description"]
  # A MapSet module attribute leaks opaque internals to Dialyzer on Elixir 1.18.
  @allowed_fields List.flatten([
                    @string_fields,
                    @digest_fields,
                    @list_fields,
                    @schema_fields,
                    @optional_display_fields,
                    ["sandbox"]
                  ])
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
  @header_name_regex ~r/\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+\z/
  @header_primitive_types ~w(boolean integer string)
  @icon_fields ~w(mimeType sizes src theme)
  @icon_size_regex ~r/\A[1-9][0-9]*x[1-9][0-9]*\z/
  @icon_themes ~w(dark light)
  @ui_visibility ~w(app model)
  @control_regex ~r/[\x00-\x1f\x7f]/

  @typedoc "A closed manifest validation or comparison failure."
  @type error ::
          :invalid_manifest
          | :invalid_header_annotation
          | :sensitive_header_param
          | :suspicious_required_param
          | :unsupported_number_range
          | :manifest_digest_mismatch
          | :schema_digest_mismatch

  @typedoc """
  A validated capability manifest.

  `preimage` is the exact canonical map hashed into `digest`. Optional
  `*_sha256` fields are `nil` when the corresponding carried value is absent.
  """
  @type t :: %__MODULE__{
          allowed_sink_zones: [String.t()] | nil,
          allowed_source_zones: [String.t()] | nil,
          annotations: map() | nil,
          annotations_sha256: String.t() | nil,
          audience: [String.t()] | nil,
          description: String.t(),
          description_sha256: String.t(),
          expires_at: String.t(),
          icons: [map()] | nil,
          icons_sha256: String.t() | nil,
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
          title: String.t() | nil,
          title_sha256: String.t() | nil,
          ui: map() | nil,
          ui_sha256: String.t() | nil,
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
            icons: nil,
            icons_sha256: nil,
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
            title: nil,
            title_sha256: nil,
            ui: nil,
            ui_sha256: nil,
            version: nil,
            preimage: %{},
            digest: nil

  @doc """
  Validates and normalizes a carried capability manifest.

  The manifest must use `sigil_guard_capability_manifest/v2`, contain only
  known fields, and carry values that agree with any supplied digest fields.
  Lists that participate in canonicalization must already be sorted and
  duplicate-free.

  Returns `{:ok, manifest}` with the canonical preimage and digest, or a typed
  error. Suspicious required parameters are reported separately so a host can
  require explicit review rather than accepting an apparently harmless schema.
  """
  @doc since: "1.0.0"
  @spec new(map()) ::
          {:ok, t()}
          | {:error,
             :invalid_manifest
             | :invalid_header_annotation
             | :sensitive_header_param
             | :suspicious_required_param
             | :unsupported_number_range}
  def new(manifest) when is_map(manifest) do
    with {:ok, manifest} <- normalize_manifest(manifest),
         :ok <- closed_fields(manifest),
         :ok <- required_fields(manifest),
         :ok <- validate_strings(manifest),
         :ok <- validate_enums(manifest),
         :ok <- validate_lists(manifest),
         :ok <- validate_sandbox(manifest),
         :ok <- validate_display_metadata(manifest),
         :ok <- validate_ui(manifest),
         :ok <- validate_header_annotations(Map.fetch!(manifest, "input_schema")),
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
  Returns the canonical digest for a manifest.

  A validated `%SigilGuard.CapabilityManifest{}` reuses its stored digest.
  Carried maps are validated and normalized first.
  """
  @doc since: "1.0.0"
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
  Compares an observed manifest with a pinned manifest.

  Schema drift is reported separately from other manifest drift so callers can
  explain why cached approval became invalid. Both inputs are fully validated;
  equality of caller-supplied digest strings alone is never sufficient.
  """
  @doc since: "1.0.0"
  @spec verify(t() | map(), map()) ::
          :ok
          | {:error,
             :manifest_digest_mismatch
             | :schema_digest_mismatch
             | :invalid_header_annotation
             | :sensitive_header_param
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
      |> Enum.all?(&(&1 in @allowed_fields))

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
      timestamp_field(manifest, "expires_at")
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

  defp validate_display_metadata(manifest) do
    with :ok <- optional_non_empty_string(manifest, "title") do
      optional_icons(manifest)
    end
  end

  defp optional_non_empty_string(manifest, field) do
    case Map.fetch(manifest, field) do
      :error -> :ok
      {:ok, value} when is_binary(value) and value != "" -> :ok
      _ -> {:error, :invalid_manifest}
    end
  end

  defp optional_icons(manifest) do
    case Map.fetch(manifest, "icons") do
      :error ->
        :ok

      {:ok, icons} when is_list(icons) ->
        if Enum.all?(icons, &valid_icon?/1), do: :ok, else: {:error, :invalid_manifest}

      _ ->
        {:error, :invalid_manifest}
    end
  end

  defp valid_icon?(icon) when is_map(icon) do
    src = Map.get(icon, "src")
    mime_type = Map.get(icon, "mimeType")
    sizes = Map.get(icon, "sizes")
    theme = Map.get(icon, "theme")

    valid_icon_keys?(icon) and valid_icon_src?(src) and
      valid_icon_mime_type?(mime_type) and valid_icon_sizes?(sizes) and
      (is_nil(theme) or theme in @icon_themes)
  end

  defp valid_icon?(_), do: false

  defp valid_icon_keys?(icon), do: Enum.all?(Map.keys(icon), &(&1 in @icon_fields))

  defp valid_icon_src?(src) when is_binary(src) do
    not Regex.match?(@control_regex, src) and valid_icon_source?(src)
  end

  defp valid_icon_src?(_), do: false

  defp valid_icon_source?("data:image/" <> _ = src) do
    src
    |> String.split(";base64,", parts: 2)
    |> valid_data_icon_parts?()
  end

  defp valid_icon_source?(src) do
    case URI.new(src) do
      {:ok, %URI{scheme: "https", host: host, userinfo: nil}} ->
        is_binary(host) and host != ""

      _ ->
        false
    end
  end

  defp valid_data_icon_parts?(["data:image/" <> subtype, encoded]) do
    subtype != "" and encoded != "" and match?({:ok, _}, Base.decode64(encoded))
  end

  defp valid_data_icon_parts?(_), do: false

  defp valid_icon_mime_type?(nil), do: true

  defp valid_icon_mime_type?(mime_type),
    do:
      is_binary(mime_type) and String.starts_with?(mime_type, "image/") and
        not Regex.match?(@control_regex, mime_type)

  defp valid_icon_sizes?(nil), do: true

  defp valid_icon_sizes?(sizes) when is_list(sizes) do
    sizes == Enum.uniq(sizes) and
      Enum.all?(sizes, &(&1 == "any" or (is_binary(&1) and Regex.match?(@icon_size_regex, &1))))
  end

  defp valid_icon_sizes?(_), do: false

  defp validate_ui(manifest) do
    case Map.fetch(manifest, "ui") do
      :error ->
        :ok

      {:ok, %{"visibility" => visibility} = ui} when is_list(visibility) ->
        uri = Map.get(ui, "resource_uri")

        if valid_ui_keys?(ui) and valid_ui_uri?(uri) and valid_visibility?(visibility) do
          :ok
        else
          {:error, :invalid_manifest}
        end

      _ ->
        {:error, :invalid_manifest}
    end
  end

  defp valid_ui_keys?(ui),
    do: Enum.all?(Map.keys(ui), &(&1 in ["resource_uri", "visibility"]))

  defp valid_ui_uri?(nil), do: true

  defp valid_ui_uri?(uri) when is_binary(uri),
    do:
      String.starts_with?(uri, "ui://") and byte_size(uri) > byte_size("ui://") and
        not Regex.match?(@control_regex, uri)

  defp valid_ui_uri?(_), do: false

  defp valid_visibility?(visibility) do
    visibility != [] and visibility == Enum.sort(visibility) and
      visibility == Enum.uniq(visibility) and
      Enum.all?(visibility, &(&1 in @ui_visibility))
  end

  defp validate_header_annotations(schema) when is_map(schema) do
    annotations = header_annotations(schema, [], nil, true)

    with :ok <- validate_each_header_annotation(annotations),
         :ok <- validate_unique_header_names(annotations) do
      reject_sensitive_header_params(annotations)
    end
  end

  defp validate_header_annotations(_), do: {:error, :invalid_manifest}

  defp header_annotations(%{} = schema, acc, property_name, reachable) do
    acc =
      case Map.fetch(schema, "x-mcp-header") do
        {:ok, header} ->
          [{property_name, header, Map.get(schema, "type"), reachable} | acc]

        :error ->
          acc
      end

    Enum.reduce(schema, acc, fn
      {"properties", properties}, found when is_map(properties) and reachable ->
        Enum.reduce(properties, found, fn {name, property}, nested ->
          header_annotations(property, nested, name, true)
        end)

      {"x-mcp-header", _}, found ->
        found

      {_, value}, found ->
        header_annotations(value, found, nil, false)
    end)
  end

  defp header_annotations(list, acc, _, _) when is_list(list) do
    Enum.reduce(list, acc, fn value, found ->
      header_annotations(value, found, nil, false)
    end)
  end

  defp header_annotations(_, acc, _, _), do: acc

  defp validate_each_header_annotation(annotations) do
    if Enum.all?(annotations, fn
         {name, header, type, true}
         when is_binary(name) and is_binary(header) and header != "" and
                type in @header_primitive_types ->
           Regex.match?(@header_name_regex, header)

         _ ->
           false
       end) do
      :ok
    else
      {:error, :invalid_header_annotation}
    end
  end

  defp validate_unique_header_names(annotations) do
    names = Enum.map(annotations, fn {_, header, _, _} -> String.downcase(header) end)

    if names == Enum.uniq(names), do: :ok, else: {:error, :invalid_header_annotation}
  end

  defp reject_sensitive_header_params(annotations) do
    if Enum.any?(annotations, fn {name, _, _, _} -> suspicious_name?(name) end),
      do: {:error, :sensitive_header_param},
      else: :ok
  end

  defp computed_fields(manifest) do
    with {:ok, description_sha256} <- sha256_bytes(Map.fetch!(manifest, "description")),
         {:ok, input_schema_sha256} <- sha256_jcs(Map.fetch!(manifest, "input_schema")),
         {:ok, annotations_sha256} <- optional_sha256_jcs(manifest, "annotations"),
         {:ok, output_schema_sha256} <- optional_sha256_jcs(manifest, "output_schema"),
         {:ok, title_sha256} <- optional_sha256_bytes(manifest, "title"),
         {:ok, icons_sha256} <- optional_sha256_jcs(manifest, "icons"),
         {:ok, ui_sha256} <- optional_sha256_jcs(manifest, "ui"),
         suspicious_params <- suspicious_params(Map.fetch!(manifest, "input_schema")) do
      {:ok,
       %{
         "annotations_sha256" => annotations_sha256,
         "description_sha256" => description_sha256,
         "icons_sha256" => icons_sha256,
         "input_schema_sha256" => input_schema_sha256,
         "output_schema_sha256" => output_schema_sha256,
         "title_sha256" => title_sha256,
         "ui_sha256" => ui_sha256,
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
    |> maybe_put("title_sha256", Map.fetch!(computed, "title_sha256"))
    |> maybe_put("icons_sha256", Map.fetch!(computed, "icons_sha256"))
    |> maybe_put("ui_sha256", Map.fetch!(computed, "ui_sha256"))
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
      icons: Map.get(manifest, "icons"),
      icons_sha256: Map.fetch!(computed, "icons_sha256"),
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
      title: Map.get(manifest, "title"),
      title_sha256: Map.fetch!(computed, "title_sha256"),
      ui: Map.get(manifest, "ui"),
      ui_sha256: Map.fetch!(computed, "ui_sha256"),
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

  defp optional_sha256_bytes(manifest, field) do
    case Map.fetch(manifest, field) do
      {:ok, value} -> sha256_bytes(value)
      :error -> {:ok, nil}
    end
  end

  defp sha256_jcs(value) do
    case JCS.encode(value) do
      {:ok, canonical} -> {:ok, sha256_hex(canonical)}
      {:error, :unsupported_number_range} -> {:error, :unsupported_number_range}
      {:error, _} -> {:error, :invalid_manifest}
    end
  end

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

  defp timestamp_field(manifest, field) do
    value = Map.get(manifest, field)

    with true <- is_binary(value),
         true <- Regex.match?(@timestamp_regex, value),
         {:ok, _, 0} <- DateTime.from_iso8601(value) do
      :ok
    else
      _ -> {:error, :invalid_manifest}
    end
  end

  defp maybe_put(map, _, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
