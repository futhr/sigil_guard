defmodule SigilGuard.Decision do
  @moduledoc """
  Runtime gate decision returned by boundary-aware SigilGuard checks.

  `:verdict` keeps compatibility with the existing policy vocabulary:
  `:allowed`, `:blocked`, or `{:confirm, reason}`. `:action` describes
  what the caller should do with the content at the boundary.
  """

  @type action :: :allow | :redact | :quarantine | :block | :confirm
  @type verdict :: SigilGuard.Policy.verdict()

  @type t :: %__MODULE__{
          verdict: verdict(),
          action: action(),
          reason: String.t() | nil,
          phase: SigilGuard.Context.phase() | SigilGuard.Lifecycle.phase(),
          risk_level: SigilGuard.Policy.risk_level(),
          trust_level: SigilGuard.Identity.trust_level(),
          hits: [SigilGuard.Patterns.scan_hit()],
          indicators: [map()],
          sanitized_text: String.t() | nil,
          content_hash: String.t() | nil,
          audit_metadata: map()
        }

  @enforce_keys [:verdict, :action, :phase, :risk_level, :trust_level]
  defstruct [
    :verdict,
    :action,
    :reason,
    :phase,
    :risk_level,
    :trust_level,
    :sanitized_text,
    :content_hash,
    hits: [],
    indicators: [],
    audit_metadata: %{}
  ]

  @doc "Return true when the decision allows the boundary crossing."
  @spec allowed?(t()) :: boolean()
  def allowed?(%__MODULE__{verdict: :allowed}), do: true
  def allowed?(_), do: false

  @doc "Return true when the decision blocks the boundary crossing."
  @spec blocked?(t()) :: boolean()
  def blocked?(%__MODULE__{verdict: :blocked}), do: true
  def blocked?(_), do: false

  @doc "Return true when the decision requires confirmation."
  @spec confirm?(t()) :: boolean()
  def confirm?(%__MODULE__{verdict: {:confirm, _}}), do: true
  def confirm?(_), do: false
end
