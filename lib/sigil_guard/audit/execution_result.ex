defmodule SigilGuard.Audit.ExecutionResult do
  @moduledoc """
  Typed execution result for audit events.

  Matches the `ExecutionResult` struct from the `sigil-protocol` Rust crate (v0.1.5).

  ## Fields

    * `:success` — whether execution completed successfully
    * `:exit_code` — process exit code (if applicable)
    * `:duration_ms` — execution duration in milliseconds
    * `:error` — error message (if failed)

  ## Example

      %SigilGuard.Audit.ExecutionResult{
        success: true,
        exit_code: 0,
        duration_ms: 42,
        error: nil
      }

  """

  @type t :: %__MODULE__{
          success: boolean() | nil,
          exit_code: integer() | nil,
          duration_ms: non_neg_integer() | nil,
          error: String.t() | nil
        }

  defstruct [:success, :exit_code, :duration_ms, :error]
end
