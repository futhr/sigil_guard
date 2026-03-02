defmodule SigilGuard.Backend do
  @moduledoc """
  Behaviour for SigilGuard processing backends.

  All backends must implement this behaviour to be used
  interchangeably by the SigilGuard API. This enables swapping
  between different processing strategies:

    * `:elixir` - Pure Elixir using OTP `:crypto` (default, safe)
    * `:nif` - Rust NIF wrapping `sigil-protocol` crate (fastest)

  ## Configuration

      config :sigil_guard,
        backend: :elixir  # :elixir | :nif

  ## Example

      # Get the configured backend module
      backend = SigilGuard.Backend.impl()

      # Scan text
      {:ok, "safe"} = backend.scan("safe", [])

  """

  alias SigilGuard.Audit
  alias SigilGuard.Identity
  alias SigilGuard.Patterns
  alias SigilGuard.Policy

  @typedoc "Backend module types"
  @type backend_module :: SigilGuard.Backend.Elixir | SigilGuard.Backend.NIF

  @typedoc "Backend configuration atoms"
  @type backend_type :: :elixir | :nif

  # -- Scanning --

  @doc "Scan text for sensitive content."
  @callback scan(text :: String.t(), opts :: keyword()) ::
              {:ok, String.t()} | {:hit, [Patterns.scan_hit()]}

  @doc "Replace matched regions with replacement hints."
  @callback redact(text :: String.t(), hits :: [Patterns.scan_hit()], opts :: keyword()) ::
              String.t()

  @doc "Scan and redact in a single pass."
  @callback scan_and_redact(text :: String.t(), opts :: keyword()) :: String.t()

  # -- Envelope --

  @doc "Produce canonical byte representation for signing."
  @callback canonical_bytes(
              identity :: String.t(),
              verdict :: SigilGuard.Envelope.verdict(),
              timestamp :: String.t(),
              nonce_hex :: String.t()
            ) :: binary()

  @doc "Sign an envelope."
  @callback envelope_sign(
              identity :: String.t(),
              verdict :: SigilGuard.Envelope.verdict(),
              opts :: keyword()
            ) :: SigilGuard.Envelope.t()

  @doc "Verify an envelope's signature."
  @callback envelope_verify(envelope :: SigilGuard.Envelope.t(), public_key_b64u :: String.t()) ::
              :ok | {:error, term()}

  # -- Policy --

  @doc "Evaluate an action against a trust level."
  @callback evaluate_policy(
              action :: String.t(),
              trust_level :: Identity.trust_level(),
              opts :: keyword()
            ) :: Policy.verdict()

  @doc "Classify the risk level of an action."
  @callback classify_risk(action :: String.t(), opts :: keyword()) :: Policy.risk_level()

  # -- Audit --

  @doc "Sign an audit event, linking it to the previous event in the chain."
  @callback audit_sign_event(event :: Audit.t(), key :: binary(), prev_hmac :: String.t() | nil) ::
              Audit.t()

  @doc "Verify the integrity of an audit event chain."
  @callback audit_verify_chain(events :: [Audit.t()], key :: binary()) ::
              :ok | {:broken, non_neg_integer()}

  @doc """
  Returns the backend implementation module based on configuration.

  ## Examples

      iex> SigilGuard.Backend.impl()
      SigilGuard.Backend.Elixir

  """
  @spec impl() :: backend_module()
  def impl do
    case Application.get_env(:sigil_guard, :backend, :elixir) do
      :elixir -> SigilGuard.Backend.Elixir
      :nif -> SigilGuard.Backend.NIF
      module when is_atom(module) -> module
    end
  end

  @doc """
  Checks if a backend is available on this system.

  ## Examples

      iex> SigilGuard.Backend.available?(:elixir)
      true

  """
  @spec available?(backend_type()) :: boolean()
  def available?(:elixir), do: true

  def available?(:nif) do
    Code.ensure_loaded?(SigilGuard.Backend.NIF.Native) and
      function_exported?(SigilGuard.Backend.NIF.Native, :scan, 2)
  end

  @doc """
  Returns a list of all available backends on this system.
  """
  @spec available_backends() :: [backend_type()]
  def available_backends do
    Enum.filter([:elixir, :nif], &available?/1)
  end
end
