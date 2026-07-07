defmodule SigilGuard.Decision do
  @moduledoc """
  Runtime gate decision returned by boundary-aware SigilGuard checks.

  `:action` carries the unified verdict vocabulary (SP.07 V3 Decision
  Contract): `:allow | :redact | :confirm | :quarantine | :block`, totally
  ordered `:allow < :redact < :confirm < :quarantine < :block`. `:verdict`
  keeps the v2 dual vocabulary (`:allowed | :blocked | {:confirm, reason}`)
  populated alongside for compatibility; it is removed in the M6 removal wave.

  V3 adds `matched_rules` and `evidence_refs` so verdicts are explainable and
  evidence-linked without raw payloads, and surfaces the boundary labels
  (`source`, `sink`, `trust_zone`, `actor`, `resource`, `phase`) on the
  decision.
  """

  @type action :: :allow | :redact | :quarantine | :block | :confirm
  @type verdict :: SigilGuard.Policy.verdict()

  @typedoc "A rule that contributed to the verdict (SP.07); mirrors SP.01 `predicate.matched_rules`."
  @type matched_rule :: %{rule_id: String.t(), explanation: String.t()}

  @type t :: %__MODULE__{
          verdict: verdict(),
          action: action(),
          reason: String.t() | nil,
          phase: SigilGuard.Context.phase() | SigilGuard.Lifecycle.phase(),
          risk_level: SigilGuard.Policy.risk_level(),
          trust_level: SigilGuard.Identity.trust_level(),
          hits: [SigilGuard.Patterns.scan_hit()],
          indicators: [map()],
          matched_rules: [matched_rule()],
          evidence_refs: [String.t()],
          source: atom() | String.t() | nil,
          sink: atom() | String.t() | nil,
          trust_zone: atom() | String.t() | nil,
          actor: String.t() | nil,
          resource: String.t() | nil,
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
    :source,
    :sink,
    :trust_zone,
    :actor,
    :resource,
    hits: [],
    indicators: [],
    matched_rules: [],
    evidence_refs: [],
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
