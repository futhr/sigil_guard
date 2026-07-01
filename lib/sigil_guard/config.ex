defmodule SigilGuard.Config do
  @moduledoc """
  Configuration access for SigilGuard.

  All settings are read from application env under `:sigil_guard`.

  ## Options

    * `:backend` — Processing backend. Only `:elixir` is supported.
      Default: `:elixir`

    * `:protocol_profile` — SIGIL compatibility profile:
      `:auto`, `:legacy_sigil_guard`, `:sigil_reference_0_1`, or
      `:sigil_spec_draft_2026_02`.
      Default: `:auto`

    * `:registry_url` — Base URL for the SIGIL registry REST API.
      Default: `"https://registry.sigil-protocol.org"`

    * `:registry_ttl_ms` — Time-to-live for cached registry bundles in milliseconds.
      Default: `3_600_000` (1 hour)

    * `:registry_timeout_ms` — HTTP timeout for registry requests.
      Default: `5_000` (5 seconds)

    * `:registry_retry_ms` — Retry interval after a failed registry fetch,
      so the cache does not wait a full TTL with stale data.
      Default: `60_000` (1 minute)

    * `:registry_enabled` — Whether to start the registry cache on application boot.
      Default: `false`

    * `:registry_require_signed_bundles` — Whether registry pattern bundles
      must carry valid Ed25519 provenance before loading.
      Default: `false`

    * `:registry_bundle_public_keys` — Map of registry bundle issuer to
      base64/base64url Ed25519 public key.
      Default: `%{}`

    * `:registry_bundle_max_age_seconds` — Maximum signed bundle age in
      seconds before quarantine. `nil` disables age enforcement.
      Default: `nil`

    * `:registry_bundle_clock_skew_seconds` — Allowed future `issued_at`
      skew for signed bundles.
      Default: `60`

    * `:scanner_patterns` — Pattern source: `:built_in` or `:registry`.
      Default: `:built_in`

  """

  @doc "Return the configured processing backend."
  @spec backend() :: :elixir | module()
  def backend do
    Application.get_env(:sigil_guard, :backend, :elixir)
  end

  @default_registry_url "https://registry.sigil-protocol.org"
  @default_ttl_ms :timer.hours(1)
  @default_timeout_ms 5_000
  @default_retry_ms :timer.minutes(1)
  @default_protocol_profile :auto
  @default_bundle_max_age_seconds nil
  @default_bundle_clock_skew_seconds 60

  @doc "Return the configured SIGIL compatibility profile."
  @spec protocol_profile() :: SigilGuard.Profile.t()
  def protocol_profile do
    :sigil_guard
    |> Application.get_env(:protocol_profile, @default_protocol_profile)
    |> SigilGuard.Profile.normalize!()
  end

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

  @doc "Return the retry interval in milliseconds after a failed registry fetch."
  @spec registry_retry_ms() :: non_neg_integer()
  def registry_retry_ms do
    Application.get_env(:sigil_guard, :registry_retry_ms, @default_retry_ms)
  end

  @doc "Return whether the registry cache is enabled on boot."
  @spec registry_enabled?() :: boolean()
  def registry_enabled? do
    Application.get_env(:sigil_guard, :registry_enabled, false)
  end

  @doc "Return whether registry bundles must be signed before loading."
  @spec registry_require_signed_bundles?() :: boolean()
  def registry_require_signed_bundles? do
    Application.get_env(:sigil_guard, :registry_require_signed_bundles, false)
  end

  @doc "Return trusted public keys for signed registry bundles."
  @spec registry_bundle_public_keys() :: %{optional(String.t()) => String.t()}
  def registry_bundle_public_keys do
    Application.get_env(:sigil_guard, :registry_bundle_public_keys, %{})
  end

  @doc "Return the maximum accepted signed registry bundle age in seconds, or nil."
  @spec registry_bundle_max_age_seconds() :: non_neg_integer() | nil
  def registry_bundle_max_age_seconds do
    Application.get_env(
      :sigil_guard,
      :registry_bundle_max_age_seconds,
      @default_bundle_max_age_seconds
    )
  end

  @doc "Return the accepted future issued-at clock skew for signed registry bundles."
  @spec registry_bundle_clock_skew_seconds() :: non_neg_integer()
  def registry_bundle_clock_skew_seconds do
    Application.get_env(
      :sigil_guard,
      :registry_bundle_clock_skew_seconds,
      @default_bundle_clock_skew_seconds
    )
  end

  @doc "Return the configured pattern source (`:built_in` or `:registry`)."
  @spec scanner_patterns() :: :built_in | :registry
  def scanner_patterns do
    Application.get_env(:sigil_guard, :scanner_patterns, :built_in)
  end
end
