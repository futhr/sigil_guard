defmodule SigilGuard.Application do
  @moduledoc """
  OTP application for SigilGuard.

  Starts the supervision tree that manages optional runtime services.
  When registry support is enabled (`config :sigil_guard, registry_url: "..."`),
  this starts:

    * `Finch` HTTP client pool (as `SigilGuard.Finch`)
    * `SigilGuard.Registry.Cache` GenServer for TTL-cached pattern bundles

  When registry is disabled (the default), no child processes are started
  and SigilGuard operates as a purely functional library with zero runtime
  overhead.
  """

  use Application

  @impl Application
  def start(_, _) do
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
