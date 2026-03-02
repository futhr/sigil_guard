defmodule SigilGuard.Backend.Elixir do
  @moduledoc """
  Pure-Elixir backend using OTP `:crypto`.

  This is the default backend requiring no external dependencies beyond
  OTP. It delegates to the existing SigilGuard modules:

    * `SigilGuard.Scanner` — regex-based sensitivity scanning
    * `SigilGuard.Envelope` — Ed25519 signing via `:crypto`
    * `SigilGuard.Policy` — risk classification and trust gating
    * `SigilGuard.Audit` — HMAC-SHA256 chain integrity

  ## When to Use

  Choose this backend when:

    * You want zero external build dependencies (no Rust toolchain needed)
    * Deployment simplicity is more important than raw throughput
    * You are running in environments where NIF compilation is impractical
      (e.g., Nerves, restricted CI, Fly.io without multi-stage builds)

  For higher throughput on scanning and cryptographic operations, consider
  the `SigilGuard.Backend.NIF` backend which wraps the Rust
  `sigil-protocol` reference implementation.

  ## Configuration

      config :sigil_guard,
        backend: :elixir  # default

  ## Example

      SigilGuard.Backend.Elixir.scan("API_KEY=sk_live_abc123", [])
      #=> {:hit, [%{type: :api_key, match: "sk_live_abc123", ...}]}

      SigilGuard.Backend.Elixir.classify_risk("read_file", [])
      #=> :low

  """

  @behaviour SigilGuard.Backend

  # -- Scanning --

  @impl SigilGuard.Backend
  def scan(text, opts), do: SigilGuard.Scanner.scan(text, opts)

  @impl SigilGuard.Backend
  def redact(text, hits, opts), do: SigilGuard.Scanner.redact(text, hits, opts)

  @impl SigilGuard.Backend
  def scan_and_redact(text, opts), do: SigilGuard.Scanner.scan_and_redact(text, opts)

  # -- Envelope --

  @impl SigilGuard.Backend
  def canonical_bytes(identity, verdict, timestamp, nonce_hex) do
    SigilGuard.Envelope.canonical_bytes(identity, verdict, timestamp, nonce_hex)
  end

  @impl SigilGuard.Backend
  def envelope_sign(identity, verdict, opts) do
    SigilGuard.Envelope.sign(identity, verdict, opts)
  end

  @impl SigilGuard.Backend
  def envelope_verify(envelope, public_key_b64u) do
    SigilGuard.Envelope.verify(envelope, public_key_b64u)
  end

  # -- Policy --

  @impl SigilGuard.Backend
  def evaluate_policy(action, trust_level, opts) do
    SigilGuard.Policy.evaluate(action, trust_level, opts)
  end

  @impl SigilGuard.Backend
  def classify_risk(action, opts), do: SigilGuard.Policy.classify_risk(action, opts)

  # -- Audit --

  @impl SigilGuard.Backend
  def audit_sign_event(event, key, prev_hmac) do
    SigilGuard.Audit.sign_event(event, key, prev_hmac)
  end

  @impl SigilGuard.Backend
  def audit_verify_chain(events, key) do
    SigilGuard.Audit.verify_chain(events, key)
  end
end
