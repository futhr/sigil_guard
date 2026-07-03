defmodule SigilGuard.Application do
  @moduledoc """
  OTP application for SigilGuard.

  On boot, creates the default ETS table backing
  `SigilGuard.Policy.rate_check/2`, the replay store, and the trust-bundle
  cache so that they are owned by a process that lives as long as the
  application.

  Starts the supervision tree that manages optional runtime services.
  When legacy remote-bundle support is enabled
  (`config :sigil_guard, registry_enabled: true`), this starts:

    * `Finch` HTTP client pool (as `SigilGuard.Finch`)
    * `SigilGuard.Registry.Cache` GenServer for TTL-cached compatibility bundles

  When remote-bundle support is disabled (the default), no child processes are
  started and SigilGuard operates as a purely functional library.
  """

  use Application

  @impl Application
  def start(_, _) do
    config = SigilGuard.Config.validate!()
    SigilGuard.Policy.ensure_rate_table()
    SigilGuard.ReplayStore.ensure_table()
    SigilGuard.TrustBundle.Cache.ensure_table()
    SigilGuard.TrustBundle.Quarantine.ensure_table()
    SigilGuard.TrustBundle.load_configured!(config)

    children =
      if SigilGuard.Config.registry_enabled?() do
        [
          {Finch, name: SigilGuard.Finch},
          SigilGuard.Registry.Cache
        ]
      else
        []
      end

    opts = [strategy: :one_for_one, name: SigilGuard.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
