defmodule SigilGuard.Audit.Actor do
  @moduledoc """
  Typed actor information for audit events.

  Tracks the SIGIL protocol actor shape used in audit events.

  ## Fields

    * `:channel` — interaction channel (`"cli"`, `"web"`, `"mcp"`, etc.)
    * `:user_id` — machine-readable identity (DID, principal ID)
    * `:username` — human-readable display name

  ## Example

      %SigilGuard.Audit.Actor{
        channel: "mcp",
        user_id: "did:web:alice",
        username: "Alice"
      }

  """

  @type t :: %__MODULE__{
          channel: String.t() | nil,
          user_id: String.t() | nil,
          username: String.t() | nil
        }

  defstruct [:channel, :user_id, :username]
end
