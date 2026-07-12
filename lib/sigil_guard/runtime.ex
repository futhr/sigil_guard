defmodule SigilGuard.Runtime do
  @moduledoc """
  Caller-supervised owner for SigilGuard's in-memory runtime state.

  SigilGuard starts this runtime automatically by default. To control its
  supervision-tree placement, disable automatic startup and add the child to
  the host application:

      config :sigil_guard, runtime: false

      children = [
        {SigilGuard.Runtime,
         config: [
           trust_bundle: {:priv, :my_app, "sigil/trust_bundle.json"},
           scanner_patterns: :bundle
         ]}
      ]

  Passing `:config` avoids global application environment. Include
  `runtime: false` in explicit configuration to describe that posture. When
  `:config` is omitted,
  the runtime validates configuration from `config :sigil_guard, ...` for
  backwards-compatible host configuration.

  SigilGuard's tables are intentionally process-global named tables, so a host
  should run exactly one runtime. The runtime fails fast if a stateful API was
  called first and caused another process to become a table owner.
  """

  use GenServer

  alias SigilGuard.Config
  alias SigilGuard.Policy
  alias SigilGuard.ReplayStore
  alias SigilGuard.TrustBundle
  alias SigilGuard.TrustBundle.Cache
  alias SigilGuard.TrustBundle.Quarantine

  @tables [
    :sigil_guard_rates,
    :sigil_guard_replay,
    :sigil_guard_trust_bundle,
    :sigil_guard_trust_bundle_quarantine
  ]

  @type option :: {:config, keyword()} | {:name, GenServer.name()}

  @doc "Start the runtime and take ownership of SigilGuard's named ETS tables."
  @spec start_link([option()]) :: GenServer.on_start()
  def start_link(opts \\ []) when is_list(opts) do
    {name, init_opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, init_opts, name: name)
  end

  @doc "Return the validated configuration held by a running runtime."
  @spec configuration(GenServer.server()) :: keyword()
  def configuration(server \\ __MODULE__), do: GenServer.call(server, :configuration)

  @impl GenServer
  def init(opts) do
    config = runtime_config!(opts)

    Policy.ensure_rate_table()
    ReplayStore.ensure_table()
    Cache.ensure_table()
    Quarantine.ensure_table()
    ensure_table_ownership!()
    TrustBundle.load_configured!(config)

    {:ok, config}
  end

  @impl GenServer
  def handle_call(:configuration, _, config), do: {:reply, config, config}

  defp runtime_config!(opts) do
    case Keyword.validate(opts, config: :application_env) do
      {:ok, validated} ->
        case Keyword.fetch!(validated, :config) do
          :application_env -> Config.validate!()
          config -> Config.validate!(config)
        end

      {:error, invalid} ->
        raise ArgumentError, "invalid SigilGuard.Runtime options: #{inspect(invalid)}"
    end
  end

  defp ensure_table_ownership! do
    owner = self()

    Enum.each(@tables, fn table ->
      case :ets.info(table, :owner) do
        ^owner ->
          :ok

        other ->
          raise ArgumentError,
                "SigilGuard.Runtime cannot own #{inspect(table)}; it is already owned by " <>
                  "#{inspect(other)}. Start the runtime before calling stateful APIs."
      end
    end)
  end
end
