defmodule SigilGuard.RepoPolicy.Decision do
  @moduledoc """
  Deterministic result from `SigilGuard.RepoPolicy.evaluate/2`.

  The verdict vocabulary intentionally mirrors deterministic repo governance:
  allow, require approval, or block. Decisions also carry the matched rule IDs,
  normalized changed paths, and unmatched paths so callers can audit why a repo
  change was gated.
  """

  @type verdict :: :allow | :require_approval | :block

  @type t :: %__MODULE__{
          verdict: verdict(),
          reason: String.t(),
          agent: String.t() | nil,
          action: String.t(),
          changed_paths: [String.t()],
          matched_rule_ids: [String.t()],
          unmatched_paths: [String.t()],
          digest: String.t()
        }

  @enforce_keys [
    :verdict,
    :reason,
    :action,
    :changed_paths,
    :matched_rule_ids,
    :unmatched_paths,
    :digest
  ]
  defstruct [
    :verdict,
    :reason,
    :agent,
    :action,
    :digest,
    changed_paths: [],
    matched_rule_ids: [],
    unmatched_paths: []
  ]
end
