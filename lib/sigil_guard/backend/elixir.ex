defmodule SigilGuard.Backend.Elixir do
  @moduledoc """
  Pure-Elixir backend using OTP `:crypto`.

  This is the default backend requiring no external dependencies beyond
  OTP. It delegates to the existing SigilGuard modules:

    * `SigilGuard.Scanner` — staged deterministic sensitivity scanning
    * `SigilGuard.Policy` — risk classification and trust gating
    * `SigilGuard.Audit` — HMAC-SHA256 chain integrity

  ## When to Use

  This is the only built-in backend. It keeps deployment simple, avoids
  native crash risk, and uses OTP `:crypto` plus BEAM regex/ETS primitives.

  ## Example

      {:hit, [hit]} = SigilGuard.Backend.Elixir.scan("AKIAIOSFODNN7EXAMPLE", [])
      hit.name
      # => "aws_access_key"

      SigilGuard.Backend.Elixir.classify_risk("read_file", [])
      # => :low

  """

  @behaviour SigilGuard.Backend

  @impl SigilGuard.Backend
  def scan(text, opts), do: SigilGuard.Scanner.scan(text, opts)

  @impl SigilGuard.Backend
  def redact(text, hits, opts), do: SigilGuard.Scanner.redact(text, hits, opts)

  @impl SigilGuard.Backend
  def scan_and_redact(text, opts), do: SigilGuard.Scanner.scan_and_redact(text, opts)

  @impl SigilGuard.Backend
  def evaluate_policy(action, trust_level, opts) do
    SigilGuard.Policy.evaluate(action, trust_level, opts)
  end

  @impl SigilGuard.Backend
  def classify_risk(action, opts), do: SigilGuard.Policy.classify_risk(action, opts)

  @impl SigilGuard.Backend
  def audit_sign_event(event, key, prev_hmac) do
    SigilGuard.Audit.sign_event(event, key, prev_hmac)
  end

  @impl SigilGuard.Backend
  def audit_verify_chain(events, key) do
    SigilGuard.Audit.verify_chain(events, key)
  end
end
