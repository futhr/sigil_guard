defmodule SigilGuard.Audit.Action do
  @moduledoc """
  Typed action information for audit events.

  Matches the `Action` struct from the `sigil-protocol` Rust crate (v0.1.5).

  ## Fields

    * `:description` — command or tool name being executed
    * `:risk_level` — classified risk level (`:low`, `:medium`, `:high`)
    * `:approved` — whether the user/policy authorized the action
    * `:allowed` — whether the security policy enforcement allowed it

  ## Example

      %SigilGuard.Audit.Action{
        description: "read_file",
        risk_level: :low,
        approved: true,
        allowed: true
      }

  """

  @type t :: %__MODULE__{
          description: String.t() | nil,
          risk_level: SigilGuard.Policy.risk_level() | nil,
          approved: boolean() | nil,
          allowed: boolean() | nil
        }

  defstruct [:description, :risk_level, :approved, :allowed]
end
