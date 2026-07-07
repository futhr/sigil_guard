defmodule SigilGuard.BoundaryPolicy do
  @moduledoc """
  Deterministic boundary decision kernel (SP.04).

  `evaluate/2` takes a `SigilGuard.Boundary` (or a map/keyword coercible to one)
  and returns a `SigilGuard.Decision`. Each decision source contributes at most
  one verdict from the unified vocabulary (`SigilGuard.Verdict`); the final
  verdict is the strongest contribution under the total order
  `:allow < :redact < :confirm < :quarantine < :block`.

  Combination order (SP.04, Decision Combination):

  1. Boundary validation failure blocks terminally.
  2. Kernel invariants (never overridable): `trust_zone: :untrusted` at
     `:tool_request` blocks; secret hits headed to an external sink block or
     redact per `:on_sensitive`; quarantine indicators quarantine.
  3. Policy-file `[rules]` verdict: the strongest matching rule, else the file
     `default`; a loaded policy with no `default` line contributes `:confirm`.

  Later milestones extend the middle stages (sandbox matrix, repo facts, hooks);
  this module owns the combination engine and the always-present invariants.
  """

  alias SigilGuard.Boundary
  alias SigilGuard.BoundaryPolicy.File, as: PolicyFile
  alias SigilGuard.BoundaryPolicy.Match
  alias SigilGuard.Decision
  alias SigilGuard.Telemetry
  alias SigilGuard.Verdict

  @external_sinks [:external, :network, "external", "network"]
  @secret_categories [:secret, "secret"]

  @typedoc "A compiled policy: `%{default: verdict | nil, rules: list}` or nil."
  @type policy :: %{optional(atom()) => term()} | nil

  @doc """
  Evaluate a boundary and return a `SigilGuard.Decision`.

  Options: `:policy` (compiled policy, or nil), `:on_sensitive`
  (`:block | :redact`, default `:block`).
  """
  @spec evaluate(Boundary.t() | map() | keyword(), keyword()) :: Decision.t()
  def evaluate(input, opts \\ []) do
    boundary = Boundary.new(input)

    decision =
      case Boundary.validate(boundary) do
        :ok -> decide(boundary, opts)
        {:error, reason} -> terminal_block(boundary, reason)
      end

    emit(decision)
    decision
  end

  # -- Combination ------------------------------------------------------------

  defp decide(boundary, opts) do
    contributions =
      [
        untrusted_tool_request(boundary),
        sensitive_sink(boundary, opts),
        quarantine_indicators(boundary),
        policy_contribution(boundary, opts)
      ]
      |> Enum.reject(&is_nil/1)

    verdict =
      contributions
      |> Enum.map(&elem(&1, 0))
      |> Verdict.strongest()

    matched = matched_rules(contributions, verdict)
    build_decision(boundary, verdict, matched)
  end

  defp untrusted_tool_request(%Boundary{phase: :tool_request, trust_zone: zone})
       when zone in [:untrusted, "untrusted"] do
    {:block, [rule("boundary.untrusted.tool_request", "untrusted zone may not request tools")]}
  end

  defp untrusted_tool_request(_), do: nil

  defp sensitive_sink(%Boundary{sink: sink, hits: hits}, opts) when sink in @external_sinks do
    if Enum.any?(hits, &secret_hit?/1) do
      verdict = if Keyword.get(opts, :on_sensitive, :block) == :redact, do: :redact, else: :block
      {verdict, [rule("boundary.secret.external_sink", "secret headed to an external sink")]}
    end
  end

  defp sensitive_sink(_, _), do: nil

  defp quarantine_indicators(%Boundary{indicators: indicators}) do
    if Enum.any?(indicators, &quarantine_indicator?/1) do
      {:quarantine, [rule("boundary.quarantine.indicator", "quarantine indicator present")]}
    end
  end

  defp policy_contribution(boundary, opts) do
    case Keyword.get(opts, :policy) do
      nil -> nil
      %PolicyFile{} = policy -> apply_policy_file(boundary, policy)
      policy when is_map(policy) -> default_contribution(policy)
      _ -> nil
    end
  end

  defp apply_policy_file(boundary, policy) do
    case Match.matching_rules(policy.rules, boundary) do
      [] -> default_contribution(policy)
      rules -> strongest_rule_contribution(rules)
    end
  end

  defp strongest_rule_contribution(rules) do
    verdict =
      rules
      |> Enum.map(& &1.decision)
      |> Verdict.strongest()

    matched =
      rules
      |> Enum.filter(&(&1.decision == verdict))
      |> Enum.map(&rule(&1.id, "matched policy rule #{&1.id}"))

    {verdict, matched}
  end

  defp default_contribution(policy) do
    case Map.get(policy, :default) do
      verdict when verdict in [:allow, :redact, :confirm, :quarantine, :block] ->
        {verdict, [rule("policy.default", "policy file default")]}

      _ ->
        {:confirm, [rule("policy.default.absent", "policy file has no default line")]}
    end
  end

  defp matched_rules(contributions, verdict) do
    contributions
    |> Enum.filter(fn {contribution_verdict, _} -> contribution_verdict == verdict end)
    |> Enum.flat_map(&elem(&1, 1))
  end

  # -- Predicates -------------------------------------------------------------

  defp secret_hit?(hit) when is_map(hit) do
    category(hit) in @secret_categories
  end

  defp secret_hit?(_), do: false

  defp category(hit) do
    Map.get(hit, "category") || Map.get(hit, :category)
  end

  defp quarantine_indicator?(indicator) when is_map(indicator) do
    truthy?(Map.get(indicator, "quarantine") || Map.get(indicator, :quarantine))
  end

  defp quarantine_indicator?(_), do: false

  defp truthy?(value), do: value not in [nil, false]

  # -- Decision assembly ------------------------------------------------------

  defp terminal_block(boundary, reason) do
    build_decision(boundary, :block, [rule("boundary.invalid", Atom.to_string(reason))],
      reason: reason,
      risk_level: :high
    )
  end

  defp build_decision(boundary, verdict, matched, extra \\ []) do
    reason = Keyword.get(extra, :reason, matched_reason(matched))

    %Decision{
      verdict: to_v2_verdict(verdict, reason),
      action: verdict,
      reason: reason && to_string(reason),
      phase: boundary.phase,
      risk_level: Keyword.get(extra, :risk_level, risk_level(verdict)),
      trust_level: normalize_trust(boundary.trust_level),
      hits: boundary.hits,
      indicators: boundary.indicators,
      audit_metadata: audit_metadata(boundary, verdict, matched)
    }
  end

  defp matched_reason([]), do: nil
  defp matched_reason([%{"explanation" => explanation} | _]), do: explanation

  defp to_v2_verdict(:allow, _), do: :allowed
  defp to_v2_verdict(:redact, _), do: :allowed

  defp to_v2_verdict(:confirm, reason),
    do: {:confirm, to_string(reason || "confirmation required")}

  defp to_v2_verdict(:quarantine, _), do: :blocked
  defp to_v2_verdict(:block, _), do: :blocked

  defp risk_level(verdict) when verdict in [:block, :quarantine], do: :high
  defp risk_level(verdict) when verdict in [:confirm, :redact], do: :medium
  defp risk_level(:allow), do: :low

  defp normalize_trust(level) when level in [:low, :medium, :high], do: level
  defp normalize_trust(_), do: :low

  defp audit_metadata(boundary, verdict, matched) do
    %{
      verdict: verdict,
      phase: boundary.phase,
      source: boundary.source,
      sink: boundary.sink,
      trust_zone: boundary.trust_zone,
      matched_rules: matched
    }
  end

  defp rule(id, explanation), do: %{"id" => id, "explanation" => explanation}

  defp emit(%Decision{} = decision) do
    Telemetry.emit([:sigil_guard, :policy, :decision], %{}, %{
      verdict: decision.action,
      phase: decision.phase,
      risk_level: decision.risk_level
    })
  end
end
