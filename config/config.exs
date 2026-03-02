import Config

config :sigil_guard,
  backend: :elixir,
  registry_url: "https://registry.sigil-protocol.org",
  registry_ttl_ms: :timer.hours(1),
  registry_timeout_ms: 5_000,
  registry_enabled: false,
  scanner_patterns: :built_in

import_config "#{config_env()}.exs"
