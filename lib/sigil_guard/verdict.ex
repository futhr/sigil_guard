defmodule SigilGuard.Verdict do
  @moduledoc """
  The unified 1.0 verdict vocabulary and its total order.

  Five closed verdicts, totally ordered by strictness:

      :allow < :redact < :confirm < :quarantine < :block

  Decision combination takes the strongest contribution; this module owns the
  ordering used by `SigilGuard.BoundaryPolicy` and the policy-file kernel.
  """

  @verdicts [:allow, :redact, :confirm, :quarantine, :block]
  @rank %{allow: 0, redact: 1, confirm: 2, quarantine: 3, block: 4}

  @type t :: :allow | :redact | :confirm | :quarantine | :block

  @doc "Return the five verdicts from weakest to strongest."
  @spec verdicts() :: [t(), ...]
  def verdicts, do: @verdicts

  @doc "Return `true` when `term` is a verdict."
  @spec verdict?(term()) :: boolean()
  def verdict?(term), do: term in @verdicts

  @doc "Return the strictness rank of a verdict (`:allow` is 0)."
  @spec rank(t()) :: 0..4
  def rank(verdict), do: Map.fetch!(@rank, verdict)

  @doc "Compare two verdicts by strictness."
  @spec compare(t(), t()) :: :lt | :eq | :gt
  def compare(a, b) do
    cond do
      rank(a) < rank(b) -> :lt
      rank(a) > rank(b) -> :gt
      true -> :eq
    end
  end

  @doc "Return the stricter of two verdicts."
  @spec strongest(t(), t()) :: t()
  def strongest(a, b), do: if(rank(a) >= rank(b), do: a, else: b)

  @doc """
  Return the strongest verdict in a list, or `:allow` when the list is empty.
  """
  @spec strongest([t()]) :: t()
  def strongest([]), do: :allow
  def strongest(verdicts), do: Enum.reduce(verdicts, &strongest/2)
end
