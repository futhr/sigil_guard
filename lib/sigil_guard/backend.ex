defmodule SigilGuard.Backend do
  @moduledoc """
  Behaviour for SigilGuard processing backends.

  SigilGuard now ships a single native Elixir implementation. The behaviour
  remains as an extension point for applications that need a custom scanner,
  signer, policy, or audit implementation behind the public facade.

  ## Configuration

      config :sigil_guard,
        backend: :elixir

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
  @type backend_module :: SigilGuard.Backend.Elixir | module()

  @typedoc "Backend configuration atoms"
  @type backend_type :: :elixir

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

  Accepts `:elixir` or a custom module implementing this behaviour. The
  previous `:nif` backend has been removed from the native Elixir line.
  Any other value raises `ArgumentError` immediately, rather
  than failing later with `UndefinedFunctionError` mid-operation.

  ## Examples

      iex> SigilGuard.Backend.impl()
      SigilGuard.Backend.Elixir

  """
  @spec impl() :: backend_module()
  def impl do
    case Application.get_env(:sigil_guard, :backend, :elixir) do
      :elixir ->
        SigilGuard.Backend.Elixir

      :nif ->
        raise ArgumentError,
              "configured :sigil_guard backend :nif has been removed; " <>
                "SigilGuard now runs on the native Elixir backend"

      module when is_atom(module) ->
        if Code.ensure_loaded?(module) and function_exported?(module, :scan, 2) do
          module
        else
          raise ArgumentError,
                "configured :sigil_guard backend #{inspect(module)} is not a module " <>
                  "implementing the SigilGuard.Backend behaviour; " <>
                  "expected :elixir or a backend module"
        end

      other ->
        raise ArgumentError,
              "invalid :sigil_guard backend #{inspect(other)}; " <>
                "expected :elixir or a module implementing SigilGuard.Backend"
    end
  end

  @doc """
  Checks if a backend is available on this system.

  ## Examples

      iex> SigilGuard.Backend.available?(:elixir)
      true

  """
  @spec available?(atom()) :: boolean()
  def available?(:elixir), do: true
  def available?(_), do: false

  @doc """
  Returns a list of all available backends on this system.
  """
  @spec available_backends() :: [backend_type(), ...]
  def available_backends, do: [:elixir]
end
