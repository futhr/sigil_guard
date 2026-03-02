defmodule SigilGuard do
  @moduledoc """
  SIGIL Protocol integration for Elixir.

  SigilGuard provides five security layers for MCP (Model Context Protocol)
  tool calls and AI agent interactions:

  1. **Sensitivity Scanning** — Detect credentials, API keys, and secrets in text
  2. **Envelope Signing** — Ed25519-signed `_sigil` metadata for tamper detection
  3. **Policy Enforcement** — Risk classification with trust-gated access control
  4. **Tamper-Evident Audit** — HMAC-SHA256 chain for immutable audit logs
  5. **Secure Vaulting** — Encrypted storage for sensitive values

  ## Backend Configuration

  Configure the processing backend in your application config:

      config :sigil_guard,
        backend: :elixir  # or :nif

  The `:elixir` backend (default) uses pure OTP `:crypto`.
  The `:nif` backend reimplements SIGIL protocol operations in Rust for performance.

  ## Quick Start

      # Scan text for sensitive content
      {:ok, "safe text"} = SigilGuard.scan("safe text")
      {:hit, hits} = SigilGuard.scan("AKIAIOSFODNN7EXAMPLE")

      # Redact sensitive content
      redacted = SigilGuard.scan_and_redact("key=AKIAIOSFODNN7EXAMPLE")
      # => "key=[AWS_KEY]"

      # Evaluate policy
      :allowed = SigilGuard.policy_verdict("read_file", :medium)
      :blocked = SigilGuard.policy_verdict("delete_database", :low)

  ## Architecture

  SigilGuard is designed as a set of composable modules with behaviour-based
  extension points. Each module can be used independently or combined via
  the top-level facade functions.

  See individual module documentation for detailed usage:

  - `SigilGuard.Backend` — Backend behaviour and selection
  - `SigilGuard.Scanner` — Sensitivity scanning engine
  - `SigilGuard.Patterns` — Pattern compilation and management
  - `SigilGuard.Envelope` — SIGIL envelope signing and verification
  - `SigilGuard.Policy` — Risk classification and trust gating
  - `SigilGuard.Audit` — Tamper-evident audit chain
  - `SigilGuard.Vault` — Secure secret storage
  - `SigilGuard.Identity` — Trust level hierarchy
  - `SigilGuard.Signer` — Cryptographic signing behaviour
  - `SigilGuard.Registry` — SIGIL registry REST client
  - `SigilGuard.Registry.Cache` — Registry data caching

  """

  alias SigilGuard.Backend
  alias SigilGuard.Identity
  alias SigilGuard.Patterns
  alias SigilGuard.Policy

  # -- Scanning --

  @doc """
  Scan text for sensitive content.

  Returns `{:ok, text}` if clean, or `{:hit, hits}` with match details.

  ## Options

    * `:patterns` — compiled patterns to use (default: built-in patterns)

  ## Examples

      iex> SigilGuard.scan("safe text")
      {:ok, "safe text"}

      iex> {:hit, hits} = SigilGuard.scan("Bearer sk-abc123def456ghi789jkl012mno345")
      ...> hd(hits).name
      "bearer_token"

  """
  @spec scan(String.t(), keyword()) :: {:ok, String.t()} | {:hit, [Patterns.scan_hit()]}
  def scan(text, opts \\ []), do: Backend.impl().scan(text, opts)

  @doc """
  Replace matched regions in text with replacement hints.

  ## Options

    * `:default_replacement` — fallback when a hit has no hint (default: `"[REDACTED]"`)

  """
  @spec redact(String.t(), [Patterns.scan_hit()], keyword()) :: String.t()
  def redact(text, hits, opts \\ []), do: Backend.impl().redact(text, hits, opts)

  @doc """
  Scan and redact in a single pass.

  Returns the original text if clean, or the redacted version if hits are found.

  ## Examples

      iex> SigilGuard.scan_and_redact("nothing sensitive here")
      "nothing sensitive here"

  """
  @spec scan_and_redact(String.t(), keyword()) :: String.t()
  def scan_and_redact(text, opts \\ []), do: Backend.impl().scan_and_redact(text, opts)

  # -- Policy --

  @doc """
  Evaluate an action against a trust level and return a verdict.

  Returns `:allowed`, `:blocked`, or `{:confirm, reason}`.

  ## Options

    * `:risk_level` — override the risk classification
    * `:risk_mappings` — map of action to risk level
    * `:trust_thresholds` — override default trust thresholds

  ## Examples

      iex> SigilGuard.policy_verdict("read_file", :medium)
      :allowed

      iex> SigilGuard.policy_verdict("delete_database", :low)
      :blocked

  """
  @spec policy_verdict(String.t(), Identity.trust_level(), keyword()) :: Policy.verdict()
  def policy_verdict(action, trust_level, opts \\ []) do
    Backend.impl().evaluate_policy(action, trust_level, opts)
  end
end
