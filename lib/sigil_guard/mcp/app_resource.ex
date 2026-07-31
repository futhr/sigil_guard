defmodule SigilGuard.MCP.AppResource do
  @moduledoc """
  Verifies an MCP Apps HTML resource before it reaches a renderer.

  `verify/2` accepts one entry from a `resources/read` result. It checks the
  `ui://` identifier, the MCP Apps MIME type, the text-or-Base64 content shape,
  a pinned SHA-256 digest, a bounded content size, and the resource's declared
  CSP origins, browser permissions, and dedicated app domain.

  Every external capability is deny-by-default. A declared origin, permission,
  or app domain must appear in the corresponding host allowlist. The returned
  `%SigilGuard.MCP.AppResource{}` is safe to hand to the next validation stage;
  it is not evidence that the HTML itself is benign.

  This module performs no network request and never parses or executes HTML.
  The host remains responsible for `resources/read`, HTML5 validation, iframe
  sandboxing, CSP and Permissions Policy headers, renderer resource limits,
  authorization, and audit logging.

  ## Example

      iex> html = "<!doctype html><title>Repository review</title>"
      ...>
      ...> digest =
      ...>   html
      ...>   |> then(&:crypto.hash(:sha256, &1))
      ...>   |> Base.encode16(case: :lower)
      ...>
      ...> resource = %{
      ...>   "uri" => "ui://repo/review",
      ...>   "mimeType" => "text/html;profile=mcp-app",
      ...>   "text" => html
      ...> }
      ...>
      ...> {:ok, verified} =
      ...>   SigilGuard.MCP.AppResource.verify(resource,
      ...>     expected_uri: "ui://repo/review",
      ...>     expected_sha256: digest
      ...>   )
      ...>
      ...> verified.uri
      "ui://repo/review"
  """
  @moduledoc since: "1.0.0"

  @mime_type "text/html;profile=mcp-app"
  @default_max_bytes 1_048_576
  @sha256_regex ~r/\A[0-9a-f]{64}\z/
  @control_regex ~r/[\x00-\x1f\x7f]/
  @domain_fields ~w(connectDomains resourceDomains frameDomains baseUriDomains)
  @permission_fields ~w(camera microphone geolocation clipboardWrite)
  @ui_fields ~w(csp domain permissions prefersBorder)
  @option_keys [
    :allowed_app_domains,
    :allowed_base_uri_domains,
    :allowed_connect_domains,
    :allowed_frame_domains,
    :allowed_permissions,
    :allowed_resource_domains,
    :expected_sha256,
    :expected_uri,
    :max_bytes,
    :require_digest
  ]
  @ambiguous_field :__sigil_guard_ambiguous_field__

  @typedoc """
  A digest-verified MCP Apps resource and its reviewed browser metadata.

  The struct intentionally carries the digest rather than duplicating the HTML
  bytes. The caller already owns the original `resources/read` content.
  """
  @type t :: %__MODULE__{
          uri: String.t(),
          mime_type: String.t(),
          sha256: String.t(),
          csp: map(),
          permissions: [String.t()],
          domain: String.t() | nil,
          prefers_border: boolean() | nil
        }

  @typedoc "A closed verification failure returned by `verify/2`."
  @type error ::
          :invalid_app_resource
          | :missing_resource_digest
          | :resource_digest_mismatch
          | :resource_too_large
          | :domain_not_allowed
          | :permission_not_allowed
          | :invalid_options

  @enforce_keys [:uri, :mime_type, :sha256]
  defstruct [
    :uri,
    :mime_type,
    :sha256,
    csp: %{},
    permissions: [],
    domain: nil,
    prefers_border: nil
  ]

  @doc """
  Verify one resource entry returned inside an MCP `resources/read` result.

  `:expected_sha256` is required unless `require_digest: false` explicitly
  selects a review workflow. `:expected_uri` binds the returned entry to the
  tool's declared UI resource and should be supplied in normal operation.

  CSP origins are accepted only from their matching allowlist:
  `:allowed_connect_domains`, `:allowed_resource_domains`,
  `:allowed_frame_domains`, or `:allowed_base_uri_domains`. Browser permission
  names use `:allowed_permissions`, and the host-specific `ui.domain` value
  uses `:allowed_app_domains`.

  Content is limited to 1 MiB by default. Set `:max_bytes` to another positive
  byte count when the renderer has a reviewed limit. Unknown, duplicated, or
  malformed options return `{:error, :invalid_options}`.
  """
  @doc since: "1.0.0"
  @spec verify(term(), keyword()) :: {:ok, t()} | {:error, error()}
  def verify(resource, opts \\ [])

  def verify(resource, opts) when is_map(resource) and is_list(opts) do
    with :ok <- validate_options(opts),
         {:ok, uri} <- required_string(resource, "uri", :uri),
         :ok <- validate_uri(uri, opts),
         {:ok, mime_type} <- required_string(resource, "mimeType", :mime_type),
         true <- mime_type == @mime_type,
         {:ok, content} <- resource_content(resource),
         :ok <- validate_content(content, opts),
         sha256 <- sha256_hex(content),
         :ok <- validate_digest(sha256, opts),
         {:ok, csp, permissions, domain, prefers_border} <- ui_security_metadata(resource),
         :ok <- validate_csp(csp, opts),
         :ok <- validate_app_domain(domain, opts),
         :ok <- validate_permissions(permissions, opts) do
      {:ok,
       %__MODULE__{
         uri: uri,
         mime_type: mime_type,
         sha256: sha256,
         csp: csp,
         permissions: Enum.sort(permissions),
         domain: domain,
         prefers_border: prefers_border
       }}
    else
      false -> {:error, :invalid_app_resource}
      {:error, reason} -> {:error, reason}
    end
  end

  def verify(_, opts) when not is_list(opts), do: {:error, :invalid_options}
  def verify(_, _), do: {:error, :invalid_app_resource}

  defp validate_options(opts) do
    if Keyword.keyword?(opts) do
      keys = Keyword.keys(opts)

      if keys == Enum.uniq(keys) and Enum.all?(keys, &(&1 in @option_keys)) and
           valid_option_values?(opts) do
        :ok
      else
        {:error, :invalid_options}
      end
    else
      {:error, :invalid_options}
    end
  end

  defp valid_option_values?(opts) do
    checks = [
      valid_expected_uri?(Keyword.get(opts, :expected_uri)),
      valid_expected_digest?(Keyword.get(opts, :expected_sha256)),
      is_boolean(Keyword.get(opts, :require_digest, true)),
      valid_max_bytes?(Keyword.get(opts, :max_bytes, @default_max_bytes)),
      valid_app_domain_allowlist?(Keyword.get(opts, :allowed_app_domains, [])),
      valid_domain_allowlist?(
        Keyword.get(opts, :allowed_base_uri_domains, []),
        "baseUriDomains"
      ),
      valid_domain_allowlist?(
        Keyword.get(opts, :allowed_connect_domains, []),
        "connectDomains"
      ),
      valid_domain_allowlist?(
        Keyword.get(opts, :allowed_frame_domains, []),
        "frameDomains"
      ),
      valid_domain_allowlist?(
        Keyword.get(opts, :allowed_resource_domains, []),
        "resourceDomains"
      ),
      valid_allowed_permissions?(Keyword.get(opts, :allowed_permissions, []))
    ]

    Enum.all?(checks)
  end

  defp validate_uri(uri, opts) do
    expected_uri = Keyword.get(opts, :expected_uri)

    cond do
      not valid_ui_uri?(uri) -> {:error, :invalid_app_resource}
      is_nil(expected_uri) -> :ok
      expected_uri == uri -> :ok
      true -> {:error, :invalid_app_resource}
    end
  end

  defp validate_content(content, opts) do
    max_bytes = Keyword.get(opts, :max_bytes, @default_max_bytes)

    cond do
      not String.valid?(content) -> {:error, :invalid_app_resource}
      byte_size(content) > max_bytes -> {:error, :resource_too_large}
      true -> :ok
    end
  end

  defp validate_digest(actual, opts) do
    case Keyword.get(opts, :expected_sha256) do
      expected when is_binary(expected) ->
        if secure_compare(actual, expected), do: :ok, else: {:error, :resource_digest_mismatch}

      nil ->
        if Keyword.get(opts, :require_digest, true),
          do: {:error, :missing_resource_digest},
          else: :ok
    end
  end

  defp ui_security_metadata(resource) do
    meta = field(resource, "_meta", :_meta) || %{}

    with true <- is_map(meta),
         ui <- field(meta, "ui", :ui) || %{},
         true <- is_map(ui),
         true <- valid_closed_keys?(ui, @ui_fields),
         csp <- field(ui, "csp", :csp) || %{},
         permissions <- field(ui, "permissions", :permissions) || %{},
         domain <- field(ui, "domain", :domain),
         prefers_border <- field(ui, "prefersBorder", :prefersBorder),
         true <- is_map(csp) and is_map(permissions),
         true <- valid_closed_keys?(csp, @domain_fields),
         true <- valid_closed_keys?(permissions, @permission_fields),
         true <- Enum.all?(csp, fn {_, domains} -> string_list?(domains) end),
         true <- Enum.all?(permissions, fn {_, value} -> value == %{} end),
         true <- is_nil(domain) or (is_binary(domain) and domain != ""),
         true <- is_nil(prefers_border) or is_boolean(prefers_border) do
      permission_names =
        permissions
        |> Map.keys()
        |> Enum.map(&key_string/1)

      {:ok, stringify_keys(csp), permission_names, domain, prefers_border}
    else
      _ -> {:error, :invalid_app_resource}
    end
  end

  defp validate_csp(csp, opts) do
    Enum.reduce_while(@domain_fields, :ok, fn field, :ok ->
      requested = Map.get(csp, field, [])
      allowed = Keyword.get(opts, allowed_option(field), [])

      cond do
        not Enum.all?(requested, &valid_domain?(&1, field)) ->
          {:halt, {:error, :invalid_app_resource}}

        not Enum.all?(requested, &(&1 in allowed)) ->
          {:halt, {:error, :domain_not_allowed}}

        true ->
          {:cont, :ok}
      end
    end)
  end

  defp validate_permissions(permissions, opts) do
    allowed = Keyword.get(opts, :allowed_permissions, [])
    normalized = Enum.map(allowed, &key_string/1)

    if Enum.all?(permissions, &(&1 in normalized)),
      do: :ok,
      else: {:error, :permission_not_allowed}
  end

  defp validate_app_domain(nil, _), do: :ok

  defp validate_app_domain(domain, opts) do
    allowed = Keyword.get(opts, :allowed_app_domains, [])

    cond do
      not valid_app_domain?(domain) -> {:error, :invalid_app_resource}
      domain not in allowed -> {:error, :domain_not_allowed}
      true -> :ok
    end
  end

  defp valid_domain?(domain, field) when is_binary(domain) do
    allowed_schemes = if field == "connectDomains", do: ["https", "wss"], else: ["https"]
    wildcard? = wildcard_domain?(domain)

    normalized =
      domain
      |> String.replace_prefix("https://*.", "https://")
      |> String.replace_prefix("wss://*.", "wss://")

    normalized
    |> URI.new()
    |> valid_parsed_domain?(
      domain,
      normalized,
      allowed_schemes,
      wildcard_allowed?(wildcard?, field)
    )
  end

  defp valid_parsed_domain?(
         {:ok, uri},
         original,
         normalized,
         allowed_schemes,
         wildcard_allowed?
       ) do
    checks = [
      uri.scheme in allowed_schemes,
      present_host?(uri.host),
      uri.path in [nil, ""],
      is_nil(uri.query),
      is_nil(uri.fragment),
      is_nil(uri.userinfo),
      not Regex.match?(@control_regex, original),
      not String.contains?(original, [" ", "\t"]),
      not String.contains?(normalized, "*"),
      wildcard_allowed?
    ]

    Enum.all?(checks)
  end

  defp valid_parsed_domain?(_, _, _, _, _), do: false

  defp wildcard_domain?(domain) do
    Enum.any?(["https://*.", "wss://*."], &String.starts_with?(domain, &1))
  end

  defp wildcard_allowed?(false, _), do: true
  defp wildcard_allowed?(true, "resourceDomains"), do: true
  defp wildcard_allowed?(true, _), do: false

  defp valid_app_domain?(domain) do
    is_binary(domain) and domain != "" and not Regex.match?(@control_regex, domain)
  end

  defp valid_ui_uri?(uri) when is_binary(uri),
    do:
      String.starts_with?(uri, "ui://") and byte_size(uri) > byte_size("ui://") and
        not Regex.match?(@control_regex, uri)

  defp valid_ui_uri?(_), do: false

  defp valid_expected_uri?(nil), do: true
  defp valid_expected_uri?(uri), do: valid_ui_uri?(uri)

  defp valid_expected_digest?(nil), do: true

  defp valid_expected_digest?(digest) when is_binary(digest),
    do: Regex.match?(@sha256_regex, digest)

  defp valid_expected_digest?(_), do: false

  defp valid_max_bytes?(value), do: is_integer(value) and value > 0

  defp present_host?(host), do: is_binary(host) and host != ""

  defp allowed_option("connectDomains"), do: :allowed_connect_domains
  defp allowed_option("resourceDomains"), do: :allowed_resource_domains
  defp allowed_option("frameDomains"), do: :allowed_frame_domains
  defp allowed_option("baseUriDomains"), do: :allowed_base_uri_domains

  defp required_string(map, string_key, atom_key) do
    case field(map, string_key, atom_key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, :invalid_app_resource}
    end
  end

  defp resource_content(resource) do
    case {field(resource, "text", :text), field(resource, "blob", :blob)} do
      {text, nil} when is_binary(text) and text != "" ->
        {:ok, text}

      {nil, blob} when is_binary(blob) and blob != "" ->
        case Base.decode64(blob) do
          {:ok, content} when content != "" -> {:ok, content}
          _ -> {:error, :invalid_app_resource}
        end

      _ ->
        {:error, :invalid_app_resource}
    end
  end

  defp field(map, string_key, atom_key) do
    cond do
      Map.has_key?(map, string_key) and Map.has_key?(map, atom_key) -> @ambiguous_field
      Map.has_key?(map, string_key) -> Map.fetch!(map, string_key)
      Map.has_key?(map, atom_key) -> Map.fetch!(map, atom_key)
      true -> nil
    end
  end

  defp valid_closed_keys?(map, allowed) do
    normalized = Enum.map(Map.keys(map), &key_string/1)

    Enum.all?(normalized, &(&1 in allowed)) and normalized == Enum.uniq(normalized)
  end

  defp stringify_keys(map), do: Map.new(map, fn {key, value} -> {key_string(key), value} end)

  defp key_string(key) when is_atom(key), do: Atom.to_string(key)
  defp key_string(key) when is_binary(key), do: key
  defp key_string(_), do: nil

  defp string_list?(value),
    do: is_list(value) and Enum.all?(value, &is_binary/1) and value == Enum.uniq(value)

  defp valid_allowed_permissions?(permissions) when is_list(permissions) do
    normalized = Enum.map(permissions, &key_string/1)

    Enum.all?(normalized, &(&1 in @permission_fields)) and
      normalized == Enum.uniq(normalized)
  end

  defp valid_allowed_permissions?(_), do: false

  defp valid_domain_allowlist?(domains, field) do
    string_list?(domains) and Enum.all?(domains, &valid_domain?(&1, field))
  end

  defp valid_app_domain_allowlist?(domains) do
    string_list?(domains) and Enum.all?(domains, &valid_app_domain?/1)
  end

  defp sha256_hex(content), do: Base.encode16(:crypto.hash(:sha256, content), case: :lower)

  defp secure_compare(left, right), do: :crypto.hash_equals(left, right)
end
