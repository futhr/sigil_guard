defmodule SigilGuard.Registry do
  @moduledoc """
  REST client for the SIGIL registry.

  Fetches pattern bundles, resolves DIDs, and retrieves policy definitions
  from a SIGIL registry server. Uses Finch for HTTP with configurable timeouts.
  DID resolution is profile-aware and normalizes the live response shapes seen
  across SigilGuard legacy registries, reference profiles, and draft spec examples.

  `fetch_bundle/1` intentionally returns raw registry JSON. Use
  `SigilGuard.Registry.Bundle.verify/2` or `SigilGuard.Registry.Cache` when
  registry pattern bundles must pass signed provenance checks before loading.

  ## Configuration

  Set these in your application config:

      config :sigil_guard,
        registry_url: "https://registry.sigil-protocol.org",
        registry_timeout_ms: 5_000,
        registry_require_signed_bundles: true,
        registry_bundle_public_keys: %{"did:sigil:registry" => "..."},
        registry_enabled: true

  ## Usage

      {:ok, bundle} = SigilGuard.Registry.fetch_bundle()
      {:ok, verified} = SigilGuard.Registry.Bundle.verify(bundle, public_keys: keys)
      {:ok, patterns} = SigilGuard.Patterns.parse_bundle(verified.bundle)

      # Or use the cache, which verifies and quarantines before serving patterns.
      SigilGuard.Registry.Cache.status()

  """

  alias SigilGuard.Config
  alias SigilGuard.Profile
  alias SigilGuard.Telemetry

  @type fetch_result :: {:ok, map()} | {:error, term()}
  @type resolved_key :: %{
          did: String.t(),
          status: String.t() | nil,
          raw_public_key: binary(),
          public_key_b64u: String.t(),
          source_format: atom()
        }

  @doc """
  Fetch the pattern bundle from the registry.

  Returns the parsed JSON response containing patterns for sensitivity scanning.

  ## Options

    * `:url` — override registry base URL
    * `:timeout` — override request timeout in milliseconds

  """
  @spec fetch_bundle(keyword()) :: fetch_result()
  def fetch_bundle(opts \\ []) do
    url = Keyword.get(opts, :url, Config.registry_url())
    timeout = Keyword.get(opts, :timeout, Config.registry_timeout_ms())

    request_json("#{url}/patterns/bundle", timeout, %{endpoint: "patterns/bundle"})
  end

  @doc """
  Resolve a DID (Decentralized Identifier) via the registry.

  Returns the upstream DID response. Use `resolve_key/2` when you need
  normalized Ed25519 key material for envelope verification.

  ## Options

    * `:url` — override registry base URL
    * `:timeout` — override request timeout in milliseconds
    * `:profile` — compatibility profile controlling endpoint order

  """
  @spec resolve_did(String.t(), keyword()) :: fetch_result()
  def resolve_did(did, opts \\ []) do
    url = Keyword.get(opts, :url, Config.registry_url())
    timeout = Keyword.get(opts, :timeout, Config.registry_timeout_ms())

    profile =
      opts
      |> Keyword.get_lazy(:profile, &Config.protocol_profile/0)
      |> Profile.normalize!()

    profile
    |> Profile.registry_identity_endpoints()
    |> request_first_success(url, did, timeout)
  end

  @doc """
  Resolve a DID and normalize supported registry key response shapes.

  Supports:

    * Flat `"public_key"` strings
    * Draft-spec JWK-like `"public_key": {"kty": "OKP", "crv": "Ed25519", "x": "..."}`
    * Legacy DID documents with `"publicKey": [%{"publicKeyBase64" => "..."}]`
  """
  @spec resolve_key(String.t(), keyword()) :: {:ok, resolved_key()} | {:error, term()}
  def resolve_key(did, opts \\ []) do
    with {:ok, response} <- resolve_did(did, opts) do
      normalize_resolved_key(response)
    end
  end

  @doc """
  Fetch policy definitions from the registry.

  Returns a list of policy rules for action classification and trust requirements.

  ## Options

    * `:url` — override registry base URL
    * `:timeout` — override request timeout in milliseconds

  """
  @spec fetch_policies(keyword()) :: fetch_result()
  def fetch_policies(opts \\ []) do
    url = Keyword.get(opts, :url, Config.registry_url())
    timeout = Keyword.get(opts, :timeout, Config.registry_timeout_ms())

    request_json("#{url}/policies", timeout, %{endpoint: "policies"})
  end

  # -- Private --

  defp request_json(full_url, timeout, telemetry_meta) do
    Telemetry.span(
      [:sigil_guard, :registry, :fetch],
      Map.put(telemetry_meta, :url, full_url),
      fn ->
        result = do_request(full_url, timeout)

        metadata =
          case result do
            {:ok, body} -> Map.merge(telemetry_meta, %{count: map_size(body), source: :registry})
            {:error, _} -> Map.merge(telemetry_meta, %{count: 0, source: :error})
          end

        {result, metadata}
      end
    )
  end

  defp request_first_success([], _, _, _), do: {:error, :not_found}

  defp request_first_success([endpoint | rest], url, did, timeout) do
    full_url = "#{url}/#{endpoint_path(endpoint, did)}"

    case request_json(full_url, timeout, %{endpoint: Atom.to_string(endpoint)}) do
      {:ok, body} -> {:ok, body}
      {:error, _} when rest != [] -> request_first_success(rest, url, did, timeout)
      {:error, reason} -> {:error, reason}
    end
  end

  defp endpoint_path(:resolve, did), do: "resolve/#{URI.encode_www_form(did)}"
  defp endpoint_path(:identities, did), do: "identities/#{URI.encode_www_form(did)}"

  defp do_request(url, timeout) do
    request = Finch.build(:get, url, [{"accept", "application/json"}])

    case Finch.request(request, SigilGuard.Finch, receive_timeout: timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        decode_object(body)

      {:ok, %Finch.Response{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Every registry endpoint returns a JSON object; a body decoding to an
  # array or scalar is malformed and previously crashed the telemetry
  # callback (map_size on a non-map).
  defp decode_object(body) do
    case Jason.decode(body) do
      {:ok, decoded} when is_map(decoded) -> {:ok, decoded}
      {:ok, _} -> {:error, :invalid_body}
      {:error, reason} -> {:error, reason}
    end
  end

  defp normalize_resolved_key(%{"public_key" => key} = body) do
    normalize_public_key(key, body)
  end

  defp normalize_resolved_key(%{"publicKey" => keys} = body) when is_list(keys) do
    case did_doc_public_key(keys) do
      :missing ->
        {:error, :missing_public_key}

      {:ok, key, source_format} ->
        did = did_field(body, ["id", "did"])
        build_resolved_key(did, Map.get(body, "status"), key, source_format)

      :error ->
        {:error, :invalid_public_key}
    end
  end

  defp normalize_resolved_key(%{"publicKey" => _}), do: {:error, :invalid_public_key}

  defp normalize_resolved_key(_), do: {:error, :missing_public_key}

  defp normalize_public_key(%{"kty" => "OKP", "crv" => "Ed25519", "x" => key}, body)
       when is_binary(key) do
    did = did_field(body, ["did", "id"])
    build_resolved_key(did, Map.get(body, "status"), key, :jwk_okp_x)
  end

  defp normalize_public_key(key, body) when is_binary(key) do
    did = did_field(body, ["did", "id"])
    build_resolved_key(did, Map.get(body, "status"), key, :flat_public_key)
  end

  defp normalize_public_key(_, _), do: {:error, :invalid_public_key}

  defp did_doc_public_key(keys) do
    Enum.reduce_while(keys, :missing, fn key, :missing ->
      case did_doc_public_key_entry(key) do
        :skip -> {:cont, :missing}
        result -> {:halt, result}
      end
    end)
  end

  defp did_doc_public_key_entry(%{"publicKeyBase64" => key}) when is_binary(key) do
    {:ok, key, :did_doc_publicKeyBase64}
  end

  defp did_doc_public_key_entry(%{"publicKeyBase64" => _}), do: :error

  defp did_doc_public_key_entry(%{"publicKeyBase64Url" => key}) when is_binary(key) do
    {:ok, key, :did_doc_publicKeyBase64Url}
  end

  defp did_doc_public_key_entry(%{"publicKeyBase64Url" => _}), do: :error
  defp did_doc_public_key_entry(_), do: :skip

  defp did_field(body, keys) do
    Enum.reduce_while(keys, nil, fn key, nil ->
      case Map.fetch(body, key) do
        {:ok, value} -> {:halt, value}
        :error -> {:cont, nil}
      end
    end)
  end

  defp build_resolved_key(did, status, encoded_key, source_format) when is_binary(did) do
    with {:ok, raw_key} <- decode_public_key(encoded_key) do
      {:ok,
       %{
         did: did,
         status: status,
         raw_public_key: raw_key,
         public_key_b64u: Base.url_encode64(raw_key, padding: false),
         source_format: source_format
       }}
    end
  end

  defp build_resolved_key(_, _, _, _), do: {:error, :missing_did}

  defp decode_public_key(encoded_key) do
    decoded =
      decode_base64url(encoded_key) ||
        decode_base64(encoded_key)

    case decoded do
      key when is_binary(key) and byte_size(key) == 32 -> {:ok, key}
      key when is_binary(key) -> {:error, :invalid_key}
      nil -> {:error, :invalid_base64}
    end
  end

  defp decode_base64url(value) do
    with :error <- Base.url_decode64(value, padding: false),
         :error <- Base.url_decode64(value, padding: true) do
      nil
    else
      {:ok, decoded} -> decoded
    end
  end

  defp decode_base64(value) do
    with :error <- Base.decode64(value, padding: false),
         :error <- Base.decode64(value, padding: true) do
      nil
    else
      {:ok, decoded} -> decoded
    end
  end
end
