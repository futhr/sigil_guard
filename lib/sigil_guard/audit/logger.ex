defmodule SigilGuard.Audit.Logger do
  @moduledoc """
  Behaviour for audit event persistence backends.

  Implement this behaviour to persist audit events to your preferred
  storage (database, file system, external service, etc.).

  ## Example

      defmodule MyApp.DbAuditLogger do
        @behaviour SigilGuard.Audit.Logger

        @impl true
        def log(event) do
          %MyApp.AuditLog{}
          |> MyApp.AuditLog.changeset(event_to_map(event))
          |> MyApp.Repo.insert!()
          :ok
        end
      end

  """

  @doc "Persist an audit event. Returns `:ok` on success."
  @callback log(event :: SigilGuard.Audit.t()) :: :ok | {:error, term()}
end
