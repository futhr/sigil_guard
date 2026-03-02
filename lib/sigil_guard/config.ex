defmodule SigilGuard.Config do
  @moduledoc """
  Configuration access for SigilGuard.

  All settings are read from application env under `:sigil_guard`.

  ## Options

    * `:backend` — Processing backend: `:elixir` or `:nif`.
      Default: `:elixir`

    * `:registry_url` — Base URL for the SIGIL registry REST API.
      Default: `"https://registry.sigil-protocol.org"`

    * `:registry_ttl_ms` — Time-to-live for cached registry bundles in milliseconds.
      Default: `3_600_000` (1 hour)

    * `:registry_timeout_ms` — HTTP timeout for registry requests.
      Default: `5_000` (5 seconds, matching Rust reference)

    * `:registry_enabled` — Whether to start the registry cache on application boot.
      Default: `false`

    * `:scanner_patterns` — Pattern source: `:built_in` or `:registry`.
      Default: `:built_in`

  """

  @doc "Return the configured processing backend."
  @spec backend() :: :elixir | :nif | module()
  def backend do
    Application.get_env(:sigil_guard, :backend, :elixir)
  end

  @default_registry_url "https://registry.sigil-protocol.org"
  @default_ttl_ms :timer.hours(1)
  @default_timeout_ms 5_000

  @doc "Return the configured SIGIL registry base URL."
  @spec registry_url() :: String.t()
  def registry_url do
    Application.get_env(:sigil_guard, :registry_url, @default_registry_url)
  end

  @doc "Return the TTL in milliseconds for cached registry bundles."
  @spec registry_ttl_ms() :: non_neg_integer()
  def registry_ttl_ms do
    Application.get_env(:sigil_guard, :registry_ttl_ms, @default_ttl_ms)
  end

  @doc "Return the HTTP timeout in milliseconds for registry requests."
  @spec registry_timeout_ms() :: non_neg_integer()
  def registry_timeout_ms do
    Application.get_env(:sigil_guard, :registry_timeout_ms, @default_timeout_ms)
  end

  @doc "Return whether the registry cache is enabled on boot."
  @spec registry_enabled?() :: boolean()
  def registry_enabled? do
    Application.get_env(:sigil_guard, :registry_enabled, false)
  end

  @doc "Return the configured pattern source (`:built_in` or `:registry`)."
  @spec scanner_patterns() :: :built_in | :registry
  def scanner_patterns do
    Application.get_env(:sigil_guard, :scanner_patterns, :built_in)
  end
end
