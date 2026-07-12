defmodule SigilGuard.Application do
  @moduledoc """
  Starts SigilGuard's default runtime.

  SigilGuard automatically owns its process-global security state so replay
  protection and trust-bundle rollback floors cannot accidentally inherit the
  lifetime of an arbitrary caller. Hosts that need to control supervision-tree
  placement can set `config :sigil_guard, runtime: false` and supervise
  `SigilGuard.Runtime` themselves.
  """

  use Application

  @impl Application
  def start(_, _) do
    children =
      case Application.get_env(:sigil_guard, :runtime, true) do
        true -> [SigilGuard.Runtime]
        false -> []
        _ -> SigilGuard.Config.validate!()
      end

    Supervisor.start_link(children, strategy: :one_for_one, name: SigilGuard.Supervisor)
  end
end
