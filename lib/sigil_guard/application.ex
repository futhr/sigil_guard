defmodule SigilGuard.Application do
  @moduledoc """
  OTP application for SigilGuard.

  On boot, creates the default ETS table backing
  `SigilGuard.Policy.rate_check/2`, the replay store, and the trust-bundle
  cache so that they are owned by a process that lives as long as the
  application.

  Starts the supervision tree that manages optional runtime services. The 1.0
  core has no legacy registry children; trust-bundle state is owned by ETS
  tables initialized during boot.
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

    children = []

    opts = [strategy: :one_for_one, name: SigilGuard.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
