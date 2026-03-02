defmodule SigilGuard.Backend.NIF do
  @moduledoc """
  Rust NIF backend wrapping the `sigil-protocol` crate via Rustler.

  > #### Work in Progress {: .warning}
  >
  > This backend is under active development. For production use,
  > configure the `:elixir` backend instead:
  >
  >     config :sigil_guard, backend: :elixir

  This backend delegates SIGIL protocol operations to compiled Rust code
  for maximum performance and protocol parity with the reference implementation.

  ## Features

    * Lower latency for scanning and crypto operations
    * Uses Rust dirty CPU schedulers for expensive operations
    * Protocol parity with Rust `sigil-protocol` crate

  ## Trade-offs

    * **No process isolation** - NIF crash takes down the BEAM
    * Requires Rust toolchain for compilation
    * More complex deployment than Elixir backend

  ## Configuration

      config :sigil_guard,
        backend: :nif

  ## Requirements

  The Rustler NIF must be compiled:

      # Ensure Rust toolchain is installed
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

      # Compile the NIF (happens automatically with mix compile if rustler is available)
      cd native/sigil_guard_nif && cargo build --release

  """

  @behaviour SigilGuard.Backend

  require Logger

  # Native module — loads the Rustler NIF
  defmodule Native do
    @moduledoc """
    Low-level NIF function stubs for the Rust `sigil_guard_nif`
    shared library.

    Each function in this module is a NIF stub that raises
    `:nif_not_loaded` until the compiled Rust library is loaded.
    At load time, these stubs are transparently replaced by their
    Rust implementations from `native/sigil_guard_nif/src/`.

    This module is not intended for direct use — call functions
    through `SigilGuard.Backend.NIF` or the `SigilGuard` facade
    instead.
    """

    # When Rustler is available (dev/test), use it for
    # auto-compilation and NIF loading. Otherwise, fall back to
    # manual loading for environments where Rustler isn't a
    # dependency (hex users without optional Rustler).
    if Code.ensure_loaded?(Rustler) do
      use Rustler,
        otp_app: :sigil_guard,
        crate: "sigil_guard_nif"
    else
      @on_load :load_nif

      @doc false
      @spec load_nif() :: :ok
      def load_nif do
        nif_paths = [
          Application.app_dir(
            :sigil_guard,
            "priv/native/libsigil_guard_nif"
          ),
          Path.join([File.cwd!(), "priv/native/libsigil_guard_nif"]),
          Application.app_dir(
            :sigil_guard,
            "priv/native/sigil_guard_nif"
          ),
          Path.join([File.cwd!(), "priv/native/sigil_guard_nif"])
        ]

        result =
          Enum.find_value(nif_paths, :not_found, fn path ->
            case :erlang.load_nif(
                   String.to_charlist(path),
                   0
                 ) do
              :ok -> :ok
              {:error, {:reload, _msg}} -> :ok
              {:error, {:upgrade, _msg}} -> :ok
              _other -> nil
            end
          end)

        case result do
          :ok -> :ok
          :not_found -> :ok
        end
      end
    end

    # NIF stubs — replaced at load time by Rust implementations

    @doc false
    @spec scan(String.t(), term()) :: {:ok, String.t()} | {:hit, list()}
    def scan(_text, _opts), do: :erlang.nif_error(:nif_not_loaded)

    @doc false
    @spec redact(String.t(), list(), term()) :: String.t()
    def redact(_text, _hits, _opts), do: :erlang.nif_error(:nif_not_loaded)

    @doc false
    @spec scan_and_redact(String.t(), term()) :: String.t()
    def scan_and_redact(_text, _opts), do: :erlang.nif_error(:nif_not_loaded)

    @doc false
    @spec canonical_bytes(String.t(), atom(), String.t(), String.t()) :: binary()
    def canonical_bytes(_identity, _verdict, _timestamp, _nonce_hex),
      do: :erlang.nif_error(:nif_not_loaded)

    @doc false
    @spec envelope_sign(String.t(), atom(), term()) :: map()
    def envelope_sign(_identity, _verdict, _opts), do: :erlang.nif_error(:nif_not_loaded)

    @doc false
    @spec envelope_verify(map(), String.t()) :: :ok | {:error, term()}
    def envelope_verify(_envelope, _public_key_b64u), do: :erlang.nif_error(:nif_not_loaded)

    @doc false
    @spec evaluate_policy(String.t(), atom(), term()) :: atom() | {atom(), String.t()}
    def evaluate_policy(_action, _trust_level, _opts), do: :erlang.nif_error(:nif_not_loaded)

    @doc false
    @spec classify_risk(String.t(), term()) :: atom()
    def classify_risk(_action, _opts), do: :erlang.nif_error(:nif_not_loaded)

    @doc false
    @spec audit_sign_event(map(), binary(), String.t() | nil) :: map()
    def audit_sign_event(_event, _key, _prev_hmac), do: :erlang.nif_error(:nif_not_loaded)

    @doc false
    @spec audit_verify_chain(list(), binary()) :: :ok | {:broken, non_neg_integer()}
    def audit_verify_chain(_events, _key), do: :erlang.nif_error(:nif_not_loaded)
  end

  # -- Backend Implementation --

  @impl SigilGuard.Backend
  def scan(text, opts), do: Native.scan(text, opts)

  @impl SigilGuard.Backend
  def redact(text, hits, opts), do: Native.redact(text, hits, opts)

  @impl SigilGuard.Backend
  def scan_and_redact(text, opts), do: Native.scan_and_redact(text, opts)

  @impl SigilGuard.Backend
  def canonical_bytes(identity, verdict, timestamp, nonce_hex) do
    Native.canonical_bytes(identity, verdict, timestamp, nonce_hex)
  end

  @impl SigilGuard.Backend
  def envelope_sign(identity, verdict, opts), do: Native.envelope_sign(identity, verdict, opts)

  @impl SigilGuard.Backend
  def envelope_verify(envelope, public_key_b64u),
    do: Native.envelope_verify(envelope, public_key_b64u)

  @impl SigilGuard.Backend
  def evaluate_policy(action, trust_level, opts),
    do: Native.evaluate_policy(action, trust_level, opts)

  @impl SigilGuard.Backend
  def classify_risk(action, opts), do: Native.classify_risk(action, opts)

  @impl SigilGuard.Backend
  def audit_sign_event(event, key, prev_hmac), do: Native.audit_sign_event(event, key, prev_hmac)

  @impl SigilGuard.Backend
  def audit_verify_chain(events, key), do: Native.audit_verify_chain(events, key)
end
