defmodule SigilGuard.Application do
  @moduledoc """
  OTP application for SigilGuard.

  On boot, creates the default ETS table backing
  `SigilGuard.Policy.rate_check/2` so that it is owned by a process that
  lives as long as the application.

  Starts the supervision tree that manages optional runtime services.
  When registry support is enabled (`config :sigil_guard, registry_enabled: true`),
  this starts:

    * `Finch` HTTP client pool (as `SigilGuard.Finch`)
    * `SigilGuard.Registry.Cache` GenServer for TTL-cached pattern bundles

  When the registry is disabled (the default), no child processes are
  started and SigilGuard operates as a purely functional library.
  """

  use Application

  @impl Application
  def start(_, _) do
    SigilGuard.Policy.ensure_rate_table()

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
