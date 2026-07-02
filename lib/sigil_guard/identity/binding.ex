defmodule SigilGuard.Identity.Binding do
  @moduledoc """
  Identity binding linking a provider credential to a trust level.

  Tracks the identity-binding shape used for trust assertions.

  ## Fields

    * `:provider` — identity provider name (`"google"`, `"eidas"`, `"did:key"`, etc.)
    * `:id` — provider-specific user identifier
    * `:trust_level` — trust level granted by this binding (`:low`, `:medium`, `:high`)
    * `:bound_at` — ISO 8601 timestamp when the binding was established

  ## Example

      %SigilGuard.Identity.Binding{
        provider: "google",
        id: "user@example.com",
        trust_level: :medium,
        bound_at: "2026-03-02T10:00:00.000Z"
      }

  """

  @type t :: %__MODULE__{
          provider: String.t() | nil,
          id: String.t() | nil,
          trust_level: SigilGuard.Identity.trust_level() | nil,
          bound_at: String.t() | nil
        }

  defstruct [:provider, :id, :trust_level, :bound_at]
end
