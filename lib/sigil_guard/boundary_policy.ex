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
  3. Sandbox mismatch matrix (SP.04): at the tool phases, the side-effect class
     and `isolation_level` select a cell; an absent/`:none` isolation defaults
     to `:quarantine` (reason `:sandbox_required`) unless a matching `[rules]`
     line carries an `isolation:` matcher - the only sanctioned weakening.
  4. Repo policy facts (SP.11): the `:repo_facts` map contributes `:block` on a
     repo `block` verdict and `:confirm` on `require_approval`; matched repo
     rules surface in the explanation.
  5. Policy-file `[rules]` verdict: the strongest matching rule, else the file
     `default`; a loaded policy with no `default` line contributes `:confirm`.
  6. Host hooks (SP.04, `SigilGuard.Hooks`): the phase-matching callback on each
     `:hooks` module may contribute `:block`/`:confirm` and advisory signals
     (risk may only raise; indicators join with source `:hook`).

  The advisory `:adaptive_detector` (SP.04, `SigilGuard.AdaptiveDetector`) is
  never a verdict source: it may only raise risk and add indicators (source
  `:adaptive`); a degraded run records `:adaptive_error` in the audit metadata.

  This module owns the combination engine and the always-present invariants.

  ## Examples

  The canonical policy's first rules encode R.06's lethal trifecta - private
  data, untrusted-content exposure, and an external sink. Low- and medium-trust
  actors are blocked outright; a high-trust actor is routed to `confirm`:

      iex> alias SigilGuard.BoundaryPolicy
      ...> alias SigilGuard.BoundaryPolicy.File, as: PolicyFile
      ...>
      ...> rules = [
      ...>   "block sensitivity:private zone:untrusted sink:external trust:low,medium",
      ...>   "confirm sensitivity:private zone:untrusted sink:external trust:high"
      ...> ]
      ...>
      ...> {:ok, policy} = PolicyFile.parse("version 3\\n[rules]\\n" <> Enum.join(rules, "\\n"))
      ...> digest = String.duplicate("a", 64)
      ...>
      ...> trifecta = [
      ...>   phase: :model_egress,
      ...>   source: :tool,
      ...>   sink: :external,
      ...>   source_sensitivity: :private,
      ...>   trust_zone: :untrusted,
      ...>   action_digest: digest,
      ...>   payload_digest: digest,
      ...>   context_digest: digest
      ...> ]
      ...>
      ...> BoundaryPolicy.evaluate([{:trust_level, :low} | trifecta], policy: policy).action
      :block
      iex> BoundaryPolicy.evaluate([{:trust_level, :high} | trifecta], policy: policy).action
      :confirm

  """

  alias SigilGuard.AdaptiveDetector
  alias SigilGuard.Boundary
  alias SigilGuard.BoundaryPolicy.File, as: PolicyFile
  alias SigilGuard.BoundaryPolicy.Match
  alias SigilGuard.Decision
  alias SigilGuard.Hooks
  alias SigilGuard.Telemetry
  alias SigilGuard.Verdict

  @external_sinks [:external, :network, "external", "network"]
  @secret_categories [:secret, "secret"]
  @risk_rank %{low: 0, medium: 1, high: 2}

  @sandbox_phases [:tool_request, :tool_result]

  # Side-effect mismatch matrix (SP.04): class -> isolation level -> verdict.
  # `:absent` is the nil / omitted level; it is not a member of the isolation
  # enum. `read`/`write`/`execute`/`network` are the matrix classes.
  @sandbox_matrix %{
    read: %{
      absent: :quarantine,
      none: :quarantine,
      container: :allow,
      vm: :allow,
      remote_attested: :allow
    },
    write: %{
      absent: :quarantine,
      none: :quarantine,
      container: :confirm,
      vm: :allow,
      remote_attested: :allow
    },
    execute: %{
      absent: :quarantine,
      none: :block,
      container: :confirm,
      vm: :allow,
      remote_attested: :allow
    },
    network: %{
      absent: :quarantine,
      none: :block,
      container: :confirm,
      vm: :allow,
      remote_attested: :allow
    }
  }

  # Manifest side-effect values (SP.03: none read write delete execute
  # privileged) plus the matrix-native `network` class, mapped to the four
  # matrix classes. Unmapped/`none` values contribute no class; the strictest
  # remaining cell decides. Fail-closed: `delete` folds into `write`,
  # `privileged` into `execute`.
  @class_of %{
    "read" => :read,
    "write" => :write,
    "delete" => :write,
    "execute" => :execute,
    "privileged" => :execute,
    "network" => :network,
    "none" => nil
  }

  @typedoc "A compiled policy: `%{default: verdict | nil, rules: list}` or nil."
  @type policy :: %{optional(atom()) => term()} | nil

  @doc """
  Evaluate a boundary and return a `SigilGuard.Decision`.

  Options: `:policy` (compiled policy, or nil), `:on_sensitive`
  (`:block | :redact`, default `:block`), `:repo_facts` (the SP.11
  `RepoPolicy.policy_facts/2` map, or nil), `:hooks` (a list of
  `SigilGuard.Hooks` modules in invocation order), `:hook_timeout_ms`
  (default `5_000`), `:adaptive_detector` (a `SigilGuard.AdaptiveDetector`
  module or nil) and `:text` (content for the detector to analyze).
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
    matching = policy_matching_rules(boundary, opts)
    hook = Hooks.dispatch(boundary, opts)
    adaptive = AdaptiveDetector.run(boundary, opts)

    contributions =
      [
        untrusted_tool_request(boundary),
        sensitive_sink(boundary, opts),
        quarantine_indicators(boundary),
        sandbox_matrix(boundary, matching),
        repo_facts(opts),
        policy_contribution(boundary, opts, matching)
      ]
      |> Enum.reject(&is_nil/1)
      |> Kernel.++(hook.contributions)

    verdict =
      contributions
      |> Enum.map(&elem(&1, 0))
      |> Verdict.strongest()

    matched = matched_rules(contributions, verdict)
    base_risk = raise_risk(risk_level(verdict), hook.risk_level)

    build_decision(boundary, verdict, matched,
      risk_level: raise_risk(base_risk, adaptive.risk_level),
      indicators: boundary.indicators ++ hook.indicators ++ adaptive.indicators,
      adaptive_error: adaptive.error
    )
  end

  defp raise_risk(base, nil), do: base

  defp raise_risk(base, hook_risk) do
    if Map.fetch!(@risk_rank, hook_risk) > Map.fetch!(@risk_rank, base), do: hook_risk, else: base
  end

  defp policy_matching_rules(boundary, opts) do
    case Keyword.get(opts, :policy) do
      %PolicyFile{} = policy -> Match.matching_rules(policy.rules, boundary)
      _ -> []
    end
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

  # Repo policy facts (SP.11). The `:repo_facts` map is the exact
  # `RepoPolicy.policy_facts/2` shape. `require_approval` maps to `:confirm`
  # (SP.07); `block` to `:block`; `allow` contributes nothing. The matched repo
  # rules surface in the decision explanation, namespaced `repo.<rule_id>`.
  defp repo_facts(opts) do
    case Keyword.get(opts, :repo_facts) do
      %{verdict: verdict} = facts -> repo_contribution(verdict, facts)
      _ -> nil
    end
  end

  defp repo_contribution(:block, facts), do: {:block, repo_rules(facts)}
  defp repo_contribution(:require_approval, facts), do: {:confirm, repo_rules(facts)}
  defp repo_contribution(_, _), do: nil

  defp repo_rules(facts) do
    case Map.get(facts, :matched_rules, []) do
      [] -> [rule("repo.default", "repo policy default: #{Map.get(facts, :default_decision)}")]
      rules when is_list(rules) -> Enum.map(rules, &repo_rule/1)
      _ -> [rule("repo.default", "repo policy verdict")]
    end
  end

  defp repo_rule(%{rule_id: id} = fact) do
    rule("repo.#{id}", Map.get(fact, :explanation) || "repo policy rule #{id}")
  end

  defp repo_rule(_), do: rule("repo.rule", "repo policy rule")

  # Side-effect mismatch matrix (SP.04). Applies only at the tool phases and
  # only when no matching `[rules]` line carries an `isolation:` matcher - that
  # explicit override is the sole sanctioned weakening of the matrix, and the
  # overriding rule's verdict flows through the normal policy contribution.
  defp sandbox_matrix(%Boundary{phase: phase} = boundary, matching)
       when phase in @sandbox_phases do
    if isolation_override?(matching) do
      nil
    else
      level = sandbox_level(boundary)
      {verdict, class} = strictest_cell(sandbox_classes(boundary), level)
      sandbox_contribution(verdict, class, level)
    end
  end

  defp sandbox_matrix(_, _), do: nil

  defp sandbox_contribution(:allow, _, _), do: nil

  defp sandbox_contribution(verdict, class, level) do
    {verdict, [rule("sandbox.matrix.#{class}.#{level}", "sandbox_required")]}
  end

  defp isolation_override?(matching) do
    Enum.any?(matching, fn %{matchers: matchers} -> Map.has_key?(matchers, "isolation") end)
  end

  defp strictest_cell(classes, level) do
    classes
    |> Enum.map(fn class -> {Map.fetch!(Map.fetch!(@sandbox_matrix, class), level), class} end)
    |> Enum.max_by(fn {verdict, _} -> Verdict.rank(verdict) end, fn -> {:allow, nil} end)
  end

  defp sandbox_level(%Boundary{sandbox: sandbox}) when is_map(sandbox) do
    case Map.get(sandbox, "isolation_level") || Map.get(sandbox, :isolation_level) do
      nil -> :absent
      level -> level
    end
  end

  defp sandbox_level(_), do: :absent

  # No verified manifest means class `execute` (SP.04); a verified manifest
  # contributes its declared side-effect classes.
  defp sandbox_classes(%Boundary{tool: tool}) when is_map(tool) do
    if verified_manifest?(tool) do
      declared_classes(tool)
    else
      [:execute]
    end
  end

  defp sandbox_classes(_), do: [:execute]

  defp verified_manifest?(tool) do
    case Map.get(tool, "manifest_digest") || Map.get(tool, :manifest_digest) do
      digest when is_binary(digest) and digest != "" -> true
      _ -> false
    end
  end

  defp declared_classes(tool) do
    case Map.get(tool, "side_effects") || Map.get(tool, :side_effects) do
      effects when is_list(effects) ->
        effects
        |> Enum.map(&Map.get(@class_of, to_string(&1), :execute))
        |> Enum.reject(&is_nil/1)
        |> Enum.uniq()

      _ ->
        [:execute]
    end
  end

  defp policy_contribution(_, opts, matching) do
    case Keyword.get(opts, :policy) do
      nil -> nil
      %PolicyFile{} = policy -> apply_policy_file(policy, matching)
      policy when is_map(policy) -> default_contribution(policy)
      _ -> nil
    end
  end

  defp apply_policy_file(policy, matching) do
    case matching do
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

  defp build_decision(boundary, verdict, matched, extra) do
    reason = Keyword.get(extra, :reason, matched_reason(matched))

    %Decision{
      verdict: to_v2_verdict(verdict, reason),
      action: verdict,
      reason: reason && to_string(reason),
      phase: boundary.phase,
      risk_level: Keyword.get(extra, :risk_level, risk_level(verdict)),
      trust_level: normalize_trust(boundary.trust_level),
      hits: boundary.hits,
      indicators: Keyword.get(extra, :indicators, boundary.indicators),
      matched_rules: typed_matched_rules(matched),
      evidence_refs: [],
      source: boundary.source,
      sink: boundary.sink,
      trust_zone: boundary.trust_zone,
      audit_metadata:
        audit_metadata(boundary, verdict, matched, Keyword.get(extra, :adaptive_error))
    }
  end

  defp typed_matched_rules(matched) do
    Enum.map(matched, &%{rule_id: &1["id"], explanation: &1["explanation"]})
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

  defp audit_metadata(boundary, verdict, matched, adaptive_error) do
    base = %{
      verdict: verdict,
      phase: boundary.phase,
      source: boundary.source,
      sink: boundary.sink,
      trust_zone: boundary.trust_zone,
      matched_rules: matched
    }

    if adaptive_error, do: Map.put(base, :adaptive_error, adaptive_error), else: base
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
