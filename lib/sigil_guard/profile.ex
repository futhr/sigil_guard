defmodule SigilGuard.Profile do
  @moduledoc """
  Compatibility profiles for existing envelope wire behavior.

  SigilGuard historically emitted title-cased envelope verdicts while later
  reference examples use lowercase verdicts. Legacy DID resolution has a similar
  split between `/identities/:did` and `/resolve/:did`. This module keeps those
  differences explicit so signing, verification, and compatibility lookup do not
  hide drift behind heuristics.
  """

  @type t ::
          :auto
          | :legacy_sigil_guard
          | :sigil_reference_0_1
          | :sigil_spec_draft_2026_02

  @type wire_verdict_format :: :lowercase | :legacy_titlecase
  @type verdict_acceptance :: :lowercase_only | :legacy_and_lowercase
  @type registry_endpoint :: :resolve | :identities

  @profiles [:auto, :legacy_sigil_guard, :sigil_reference_0_1, :sigil_spec_draft_2026_02]

  @doc "Return all supported compatibility profiles."
  @spec profiles() :: [t(), ...]
  def profiles, do: @profiles

  @doc "Normalize a profile value or raise for invalid configuration."
  @spec normalize!(t()) :: t()
  def normalize!(profile) when profile in @profiles, do: profile

  def normalize!(profile) do
    raise ArgumentError,
          "invalid :sigil_guard protocol_profile #{inspect(profile)}; " <>
            "expected one of #{inspect(@profiles)}"
  end

  @doc "Return the default wire verdict format for a profile."
  @spec wire_verdict_format(t()) :: wire_verdict_format()
  def wire_verdict_format(:legacy_sigil_guard), do: :legacy_titlecase
  def wire_verdict_format(_), do: :lowercase

  @doc "Return the verdict forms accepted during verification."
  @spec verdict_acceptance(t()) :: verdict_acceptance()
  def verdict_acceptance(:sigil_spec_draft_2026_02), do: :lowercase_only
  def verdict_acceptance(_), do: :legacy_and_lowercase

  @doc "Whether blocked envelopes must include a reason during verification."
  @spec require_blocked_reason_on_verify?(t()) :: boolean()
  def require_blocked_reason_on_verify?(:sigil_spec_draft_2026_02), do: true
  def require_blocked_reason_on_verify?(_), do: false

  @doc "Legacy DID-resolution endpoints to try, in order."
  @spec registry_identity_endpoints(t()) :: [registry_endpoint()]
  def registry_identity_endpoints(:legacy_sigil_guard), do: [:identities, :resolve]
  def registry_identity_endpoints(:sigil_spec_draft_2026_02), do: [:resolve]
  def registry_identity_endpoints(_), do: [:resolve, :identities]
end
