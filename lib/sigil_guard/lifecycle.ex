defmodule SigilGuard.Lifecycle do
  @moduledoc """
  The v3 lifecycle phase taxonomy (SP.04).

  Nine phases form a closed set shared by `SigilGuard.Boundary`, the
  `SigilGuard.Hooks` behaviour, and policy-file `phase:` matchers. Each phase is
  classified as *blockable* (a hook or policy may deny/confirm) or
  *notification-only* (evidence events that never block).

  | Phase | Blockable |
  |-------|-----------|
  | `:session_start` | no |
  | `:tool_request` | yes |
  | `:permission_requested` | yes |
  | `:permission_resolved` | yes |
  | `:tool_result` | yes |
  | `:file_changed` | yes |
  | `:model_ingress` | yes |
  | `:model_egress` | yes |
  | `:session_end` | no |

  The legacy `SigilGuard.Context` phases map onto this set:
  `:inbound_user -> :model_ingress`, `:outbound_model -> :model_egress`,
  `:repo_change -> :file_changed`; `:tool_request`/`:tool_result` are unchanged.
  """

  @phases [
    :session_start,
    :tool_request,
    :permission_requested,
    :permission_resolved,
    :tool_result,
    :file_changed,
    :model_ingress,
    :model_egress,
    :session_end
  ]

  @notify_only [:session_start, :session_end]

  @phase_strings Map.new(@phases, fn phase -> {Atom.to_string(phase), phase} end)

  @context_phase_map %{
    inbound_user: :model_ingress,
    outbound_model: :model_egress,
    repo_change: :file_changed,
    tool_request: :tool_request,
    tool_result: :tool_result
  }

  @type phase ::
          :session_start
          | :tool_request
          | :permission_requested
          | :permission_resolved
          | :tool_result
          | :file_changed
          | :model_ingress
          | :model_egress
          | :session_end

  @doc """
  Return the nine lifecycle phases in canonical order.
  """
  @spec phases() :: [phase(), ...]
  def phases, do: @phases

  @doc """
  Return `true` when `term` is a lifecycle phase.
  """
  @spec phase?(term()) :: boolean()
  def phase?(term), do: term in @phases

  @doc """
  Return `true` when `phase` may block (deny or confirm) a boundary crossing.

  Notification-only phases (`:session_start`, `:session_end`) return `false`.
  """
  @spec blockable?(phase()) :: boolean()
  def blockable?(phase) when phase in @notify_only, do: false
  def blockable?(phase) when phase in @phases, do: true
  def blockable?(_), do: false

  @doc """
  Return `true` when `phase` is notification-only (never blocks).
  """
  @spec notify_only?(phase()) :: boolean()
  def notify_only?(phase), do: phase in @notify_only

  @doc """
  Normalize an atom or string into a lifecycle phase.

  Uses a closed lookup; never calls `String.to_atom/1` on external input.
  Returns `:error` for anything outside the taxonomy.
  """
  @spec cast(term()) :: {:ok, phase()} | :error
  def cast(phase) when phase in @phases, do: {:ok, phase}

  def cast(phase) when is_binary(phase) do
    case Map.fetch(@phase_strings, phase) do
      {:ok, phase} -> {:ok, phase}
      :error -> :error
    end
  end

  def cast(_), do: :error

  @doc """
  Map a legacy `SigilGuard.Context` phase to its lifecycle phase.

  Returns `:error` for unknown context phases.
  """
  @spec from_context_phase(term()) :: {:ok, phase()} | :error
  def from_context_phase(phase) do
    case Map.fetch(@context_phase_map, phase) do
      {:ok, phase} -> {:ok, phase}
      :error -> :error
    end
  end
end
