defmodule SigilGuard.Registry do
  @moduledoc """
  REST client for the SIGIL registry.

  Fetches pattern bundles, resolves DIDs, and retrieves policy definitions
  from a SIGIL registry server. Uses Finch for HTTP with configurable timeouts.

  ## Configuration

  Set these in your application config:

      config :sigil_guard,
        registry_url: "https://registry.sigil-protocol.org",
        registry_timeout_ms: 5_000,
        registry_enabled: true

  ## Usage

      {:ok, bundle} = SigilGuard.Registry.fetch_bundle()
      {:ok, patterns} = SigilGuard.Patterns.parse_bundle(bundle)

  """

  alias SigilGuard.Config
  alias SigilGuard.Telemetry

  @type fetch_result :: {:ok, map()} | {:error, term()}

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

  Returns the DID document with public keys and service endpoints.

  ## Options

    * `:url` — override registry base URL
    * `:timeout` — override request timeout in milliseconds

  """
  @spec resolve_did(String.t(), keyword()) :: fetch_result()
  def resolve_did(did, opts \\ []) do
    url = Keyword.get(opts, :url, Config.registry_url())
    timeout = Keyword.get(opts, :timeout, Config.registry_timeout_ms())
    encoded_did = URI.encode_www_form(did)

    request_json("#{url}/identities/#{encoded_did}", timeout, %{endpoint: "identities"})
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

  defp do_request(url, timeout) do
    request = Finch.build(:get, url, [{"accept", "application/json"}])

    case Finch.request(request, SigilGuard.Finch, receive_timeout: timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        Jason.decode(body)

      {:ok, %Finch.Response{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end
end
