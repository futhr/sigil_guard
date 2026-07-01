import Config

config :sigil_guard,
  backend: :elixir,
  protocol_profile: :auto,
  registry_url: "https://registry.sigil-protocol.org",
  registry_ttl_ms: :timer.hours(1),
  registry_timeout_ms: 5_000,
  registry_retry_ms: :timer.minutes(1),
  registry_enabled: false,
  registry_require_signed_bundles: false,
  registry_bundle_public_keys: %{},
  registry_bundle_max_age_seconds: nil,
  registry_bundle_clock_skew_seconds: 60,
  scanner_patterns: :built_in

import_config "#{config_env()}.exs"
