defmodule SigilGuard.Config do
  @moduledoc """
  Configuration access for SigilGuard.

  All settings are read from application env under `:sigil_guard`.

  ## Options

    * `:backend` — Processing backend. Only `:elixir` is supported.
      Default: `:elixir`

    * `:protocol_profile` — Legacy envelope compatibility profile:
      `:auto`, `:legacy_sigil_guard`, `:sigil_reference_0_1`, or
      `:sigil_spec_draft_2026_02`.
      Default: `:auto`

    * `:registry_url` — Base URL for an explicit legacy remote-bundle
      compatibility endpoint. There is no public default.
      Default: `nil`

    * `:registry_ttl_ms` — Time-to-live for cached legacy remote bundles in milliseconds.
      Default: `3_600_000` (1 hour)

    * `:registry_timeout_ms` — HTTP timeout for legacy remote-bundle requests.
      Default: `5_000` (5 seconds)

    * `:registry_retry_ms` — Retry interval after a failed legacy remote-bundle fetch,
      so the cache does not wait a full TTL with stale data.
      Default: `60_000` (1 minute)

    * `:registry_enabled` — Whether to start the legacy remote-bundle cache
      on application boot.
      Default: `false`

    * `:registry_require_signed_bundles` — Whether remotely loaded
      compatibility bundles must carry valid Ed25519 provenance before loading.
      Default: `false`

    * `:registry_bundle_public_keys` — Map of remote bundle issuer to
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

  @default_registry_url nil
  @default_ttl_ms :timer.hours(1)
  @default_timeout_ms 5_000
  @default_retry_ms :timer.minutes(1)
  @default_protocol_profile :auto
  @default_bundle_max_age_seconds nil
  @default_bundle_clock_skew_seconds 60
  @default_attestation_ttl_ms 300_000
  @default_max_skew_ms 60_000
  @default_replay_ttl_ms 300_000

  @removed_keys [
    :backend,
    :protocol_profile,
    :registry_url,
    :registry_ttl_ms,
    :registry_timeout_ms,
    :registry_retry_ms,
    :registry_enabled,
    :registry_require_signed_bundles,
    :registry_bundle_public_keys,
    :registry_bundle_max_age_seconds,
    :registry_bundle_clock_skew_seconds
  ]

  @schema [
    trust_bundle: [
      type: {:custom, __MODULE__, :validate_trust_bundle_source, []},
      default: :none,
      doc: "Local trust-bundle source. The default `:none` disables bundle loading."
    ],
    scanner_patterns: [
      type: {:in, [:built_in, :bundle]},
      default: :built_in,
      doc: "Scanner pattern source. Use `:built_in` or `:bundle`."
    ],
    http_client: [
      type: {:or, [:atom, nil]},
      default: nil,
      doc: "Host-provided HTTP client module for audit anchor stores."
    ],
    attestation_ttl_ms: [
      type: :pos_integer,
      default: @default_attestation_ttl_ms,
      doc: "Attestation time-to-live in milliseconds."
    ],
    max_skew_ms: [
      type: :non_neg_integer,
      default: @default_max_skew_ms,
      doc: "Maximum accepted clock skew in milliseconds."
    ],
    replay_ttl_ms: [
      type: :pos_integer,
      default: @default_replay_ttl_ms,
      doc: "Replay cache time-to-live in milliseconds."
    ],
    vault_master_key: [
      type: {:or, [:string, nil]},
      default: nil,
      doc: "Optional base64-encoded vault master key."
    ],
    trust_mappings: [
      type: {:custom, __MODULE__, :validate_trust_mappings, []},
      default: [],
      doc:
        "Ordered `{pattern, trust_level}` actor-to-trust mappings (SP.10). " <>
          "Patterns are exact strings or a single trailing `*` prefix; " <>
          "`trust_level` is `:low | :medium | :high`. First match wins."
    ]
  ]

  @schema_keys Keyword.keys(@schema)

  @doc """
  Validate the v3 SigilGuard configuration surface.

  Unknown keys and removed v2 keys raise `SigilGuard.ConfigError` with a
  migration-guide pointer. The returned keyword list includes schema defaults.
  """
  @spec validate!() :: keyword()
  def validate! do
    :sigil_guard
    |> Application.get_all_env()
    |> validate!()
  end

  @doc """
  Validate explicit SigilGuard configuration options.
  """
  @spec validate!(keyword()) :: keyword()
  def validate!(opts) when is_list(opts) do
    with :ok <- reject_removed_keys(opts),
         :ok <- reject_unknown_keys(opts),
         :ok <- reject_legacy_values(opts),
         {:ok, validated} <- NimbleOptions.validate(opts, @schema),
         normalized <- normalize_validated_options(validated),
         :ok <- validate_cross_options(normalized) do
      normalized
    else
      {:error, %SigilGuard.ConfigError{} = error} ->
        raise error

      {:error, %NimbleOptions.ValidationError{} = error} ->
        key = validation_key(error)
        raise SigilGuard.ConfigError.new(key, validation_reason(error), error.message)
    end
  end

  def validate!(_) do
    raise SigilGuard.ConfigError.new(:sigil_guard, :invalid_config, "expected a keyword list")
  end

  @doc """
  Return generated documentation for the v3 configuration schema.
  """
  @spec schema_docs() :: String.t()
  def schema_docs do
    NimbleOptions.docs(@schema)
  end

  @doc "Return the configured legacy envelope compatibility profile."
  @spec protocol_profile() :: SigilGuard.Profile.t()
  def protocol_profile do
    :sigil_guard
    |> Application.get_env(:protocol_profile, @default_protocol_profile)
    |> SigilGuard.Profile.normalize!()
  end

  @doc "Return the configured legacy remote-bundle compatibility endpoint."
  @spec registry_url() :: String.t() | nil
  def registry_url do
    Application.get_env(:sigil_guard, :registry_url, @default_registry_url)
  end

  @doc "Return the TTL in milliseconds for cached legacy remote bundles."
  @spec registry_ttl_ms() :: non_neg_integer()
  def registry_ttl_ms do
    Application.get_env(:sigil_guard, :registry_ttl_ms, @default_ttl_ms)
  end

  @doc "Return the HTTP timeout in milliseconds for legacy remote-bundle requests."
  @spec registry_timeout_ms() :: non_neg_integer()
  def registry_timeout_ms do
    Application.get_env(:sigil_guard, :registry_timeout_ms, @default_timeout_ms)
  end

  @doc "Return the retry interval in milliseconds after a failed legacy remote-bundle fetch."
  @spec registry_retry_ms() :: non_neg_integer()
  def registry_retry_ms do
    Application.get_env(:sigil_guard, :registry_retry_ms, @default_retry_ms)
  end

  @doc "Return whether the legacy remote-bundle cache is enabled on boot."
  @spec registry_enabled?() :: boolean()
  def registry_enabled? do
    Application.get_env(:sigil_guard, :registry_enabled, false)
  end

  @doc "Return whether legacy remote bundles must be signed before loading."
  @spec registry_require_signed_bundles?() :: boolean()
  def registry_require_signed_bundles? do
    Application.get_env(:sigil_guard, :registry_require_signed_bundles, false)
  end

  @doc "Return trusted public keys for signed legacy remote bundles."
  @spec registry_bundle_public_keys() :: %{optional(String.t()) => String.t()}
  def registry_bundle_public_keys do
    Application.get_env(:sigil_guard, :registry_bundle_public_keys, %{})
  end

  @doc "Return the maximum accepted signed legacy remote-bundle age in seconds, or nil."
  @spec registry_bundle_max_age_seconds() :: non_neg_integer() | nil
  def registry_bundle_max_age_seconds do
    Application.get_env(
      :sigil_guard,
      :registry_bundle_max_age_seconds,
      @default_bundle_max_age_seconds
    )
  end

  @doc "Return the accepted future issued-at clock skew for signed legacy remote bundles."
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

  @doc false
  @spec validate_trust_bundle_source(term()) :: {:ok, term()} | {:error, String.t()}
  def validate_trust_bundle_source(:none), do: {:ok, :none}
  def validate_trust_bundle_source({:file, path} = source) when is_binary(path), do: {:ok, source}

  def validate_trust_bundle_source({:map, envelope} = source) when is_map(envelope),
    do: {:ok, source}

  def validate_trust_bundle_source({:binary, bytes} = source) when is_binary(bytes),
    do: {:ok, source}

  def validate_trust_bundle_source({:priv, app, path} = source)
      when is_atom(app) and is_binary(path) do
    {:ok, source}
  end

  def validate_trust_bundle_source(_) do
    {:error, "expected :none, {:file, path}, {:priv, app, path}, {:map, map}, or {:binary, bin}"}
  end

  @doc false
  @spec validate_trust_mappings(term()) :: {:ok, term()} | {:error, String.t()}
  def validate_trust_mappings(mappings) when is_list(mappings) do
    if Enum.all?(mappings, &valid_trust_mapping?/1) do
      {:ok, mappings}
    else
      {:error,
       "expected {pattern, trust_level} tuples; pattern is an exact string or a single " <>
         "trailing `*` prefix, trust_level is :low | :medium | :high"}
    end
  end

  def validate_trust_mappings(_), do: {:error, "expected a list of {pattern, trust_level} tuples"}

  defp valid_trust_mapping?({pattern, trust_level}) do
    valid_mapping_pattern?(pattern) and trust_level in [:low, :medium, :high]
  end

  defp valid_trust_mapping?(_), do: false

  # A pattern is an exact string or a single trailing `*` (prefix match); a `*`
  # in any other position, or more than one, is rejected (SP.10 closed grammar).
  defp valid_mapping_pattern?(pattern) when is_binary(pattern) do
    case :binary.matches(pattern, "*") do
      [] -> true
      [{pos, 1}] -> pos == byte_size(pattern) - 1
      _ -> false
    end
  end

  defp valid_mapping_pattern?(_), do: false

  @doc "Return the configured ordered actor-to-trust mappings (SP.10)."
  @spec trust_mappings() :: [{String.t(), SigilGuard.Identity.trust_level()}]
  def trust_mappings do
    Application.get_env(:sigil_guard, :trust_mappings, [])
  end

  defp reject_removed_keys(opts) do
    case Enum.find(opts, fn {key, _} -> key in @removed_keys end) do
      {key, _} ->
        {:error,
         SigilGuard.ConfigError.new(key, :legacy_contract_removed, "legacy config key removed")}

      nil ->
        :ok
    end
  end

  defp reject_unknown_keys(opts) do
    case Enum.find(opts, fn {key, _} -> key not in @schema_keys end) do
      {key, _} ->
        {:error, SigilGuard.ConfigError.new(key, :unknown_config_key, "unknown config key")}

      nil ->
        :ok
    end
  end

  defp reject_legacy_values(opts) do
    case Keyword.fetch(opts, :scanner_patterns) do
      {:ok, :registry} ->
        {:error,
         SigilGuard.ConfigError.new(
           :scanner_patterns,
           :legacy_contract_removed,
           "legacy :registry pattern source removed"
         )}

      _ ->
        :ok
    end
  end

  defp validate_cross_options(opts) do
    if opts[:scanner_patterns] == :bundle and opts[:trust_bundle] == :none do
      {:error,
       SigilGuard.ConfigError.new(
         :scanner_patterns,
         :invalid_config,
         ":bundle scanner patterns require a configured :trust_bundle"
       )}
    else
      :ok
    end
  end

  defp normalize_validated_options(validated) when is_map(validated), do: Map.to_list(validated)
  defp normalize_validated_options(validated), do: validated

  defp validation_key(%NimbleOptions.ValidationError{key: key}) when is_atom(key), do: key

  defp validation_reason(%NimbleOptions.ValidationError{keys_path: [key | _]}) do
    if key in @schema_keys, do: :invalid_config, else: :unknown_config_key
  end

  defp validation_reason(_), do: :invalid_config
end
