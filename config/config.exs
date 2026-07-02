import Config

config :sigil_guard,
  trust_bundle: :none,
  scanner_patterns: :built_in,
  http_client: nil,
  attestation_ttl_ms: 300_000,
  max_skew_ms: 60_000,
  replay_ttl_ms: 300_000,
  vault_master_key: nil

import_config "#{config_env()}.exs"
