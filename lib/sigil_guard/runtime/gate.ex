defmodule SigilGuard.Runtime.Gate do
  @moduledoc """
  Boundary-aware runtime gate for MCP/tool-call security.

  The gate composes existing SigilGuard primitives into a source-to-sink
  decision:

    * normalize boundary context
    * scan content for sensitive values
    * inspect untrusted tool/resource output for quarantine indicators
    * evaluate policy using action risk and trust
    * apply deterministic source-to-sink rules
    * emit telemetry without raw sensitive values

  This module is transport-agnostic. MCP adapters can call it before and
  after tool execution without SigilGuard depending on a specific MCP
  package.
  """

  alias SigilGuard.Confirmation
  alias SigilGuard.Context
  alias SigilGuard.Decision
  alias SigilGuard.Policy
  alias SigilGuard.Quarantine
  alias SigilGuard.RepoPolicy
  alias SigilGuard.RepoPolicy.Decision, as: RepoDecision
  alias SigilGuard.Scanner
  alias SigilGuard.Telemetry

  @external_sinks ~w(external network log repo tool)a

  @doc """
  Evaluate whether a payload can cross the labeled boundary.

  `payload` may be a binary or a map containing `"text"`, `"content"`,
  `"output"`, or `"body"`. `context` may be a `%SigilGuard.Context{}`,
  map, or keyword list.

  ## Options

    * `:patterns` — scanner patterns
    * `:risk_level` — override policy risk
    * `:on_sensitive` — `:block` or `:redact` for sensitive content
    * `:strict_quarantine` — block medium quarantine indicators too
  """
  @spec evaluate(term(), Context.t() | map() | keyword(), keyword()) :: Decision.t()
  def evaluate(payload, context \\ %Context{}, opts \\ []) do
    context = Context.new(context)

    decision =
      case runtime_inputs(payload, context) do
        {:ok, text, action} -> evaluate_checked(payload, context, text, action, opts)
        {:error, reason} -> malformed_input_decision(context, reason)
      end

    emit_decision(decision)
    decision
  end

  defp runtime_inputs(payload, context) do
    with {:ok, text} <- Context.fetch_text(payload),
         {:ok, action} <- Context.fetch_action_name(context, payload) do
      {:ok, text, action}
    end
  end

  defp evaluate_checked(payload, context, text, action, opts) do
    hits = scan_hits(text, opts)
    quarantine = Quarantine.inspect(text, context, opts)
    repo_policy = repo_policy_decision(payload, context, action, opts)

    risk =
      risk_level(%{
        action: action,
        context: context,
        hits: hits,
        quarantine: quarantine,
        repo_policy: repo_policy,
        opts: opts
      })

    policy_verdict =
      Policy.evaluate(action, context.trust_level, Keyword.put(opts, :risk_level, risk))

    decide(%{
      payload: payload,
      text: text,
      context: context,
      hits: hits,
      quarantine: quarantine,
      repo_policy: repo_policy,
      risk: risk,
      policy_verdict: policy_verdict,
      opts: opts
    })
  end

  defp malformed_input_decision(context, reason) do
    quarantine = Quarantine.inspect(nil, context, [])

    %Decision{
      verdict: :blocked,
      action: :block,
      reason: "Malformed runtime input: #{reason}",
      phase: context.phase,
      risk_level: :high,
      trust_level: context.trust_level,
      hits: [],
      indicators: [],
      sanitized_text: nil,
      content_hash: quarantine.content_hash,
      audit_metadata: malformed_input_audit_metadata(context, reason, quarantine.content_hash)
    }
  end

  defp malformed_input_audit_metadata(context, reason, content_hash) do
    %{
      phase: context.phase,
      actor: context.actor,
      identity: context.identity,
      origin: context.origin,
      sink: context.sink,
      tool: audit_binary(context.tool),
      mcp_server: audit_binary(context.mcp_server),
      resource_uri: audit_binary(context.resource_uri),
      trust_zone: context.trust_zone,
      trust_level: context.trust_level,
      risk_level: :high,
      verdict: :blocked,
      action: :block,
      hit_count: 0,
      indicator_count: 0,
      indicator_ids: [],
      content_hash: content_hash,
      action_digest: nil,
      runtime_input_error: reason
    }
  end

  defp audit_binary(value) when is_binary(value), do: value
  defp audit_binary(_), do: nil

  defp scan_hits(nil, _), do: []

  defp scan_hits(text, opts) do
    case Scanner.scan(text, opts) do
      {:ok, _} -> []
      {:hit, hits} -> hits
    end
  end

  defp risk_level(state) do
    Keyword.get_lazy(state.opts, :risk_level, fn ->
      cond do
        repo_policy_verdict(state.repo_policy) == :block ->
          :high

        repo_policy_verdict(state.repo_policy) == :require_approval ->
          :medium

        state.quarantine.verdict == :blocked ->
          :high

        state.quarantine.verdict == :suspicious ->
          :medium

        Enum.any?(state.hits, &(&1.severity == :high)) and external_sink?(state.context.sink) ->
          :high

        state.hits != [] ->
          :medium

        true ->
          Policy.classify_risk(state.action, state.opts)
      end
    end)
  end

  defp repo_policy_decision(_, %Context{phase: phase}, _, _) when phase != :repo_change, do: nil

  defp repo_policy_decision(payload, context, action, opts) do
    case Keyword.fetch(opts, :repo_policy) do
      {:ok, raw_policy} ->
        case RepoPolicy.compile(raw_policy) do
          {:ok, policy} ->
            RepoPolicy.evaluate(policy, repo_policy_context(payload, context, action))

          {:error, reason} ->
            {:error, reason}
        end

      :error ->
        nil
    end
  end

  defp repo_policy_context(payload, context, action) do
    %{
      identity: context.identity,
      actor: context.actor,
      action: repo_policy_action(payload, context, action),
      changed_paths: changed_paths(payload, context)
    }
  end

  defp repo_policy_action(payload, context, fallback_action) do
    cond do
      context.action != nil ->
        context.action

      context.tool != nil ->
        context.tool

      true ->
        payload_repo_policy_action(payload, fallback_action)
    end
  end

  defp payload_repo_policy_action(payload, fallback_action) when is_map(payload) do
    case first_present_value(payload, repo_policy_action_keys()) do
      {:ok, nil} -> fallback_action
      {:ok, action} -> action
      :not_found -> fallback_action
    end
  end

  defp payload_repo_policy_action(_, fallback_action), do: fallback_action

  defp repo_policy_action_keys do
    [:action, "action", :tool, "tool", :name, "name"]
  end

  defp changed_paths(payload, context) do
    case first_present_value(context.metadata, changed_path_context_keys()) do
      {:ok, value} -> value
      :not_found -> payload_changed_paths(payload)
    end
  end

  defp payload_changed_paths(payload) do
    case first_present_value(payload, changed_path_payload_keys()) do
      {:ok, value} -> value
      :not_found -> []
    end
  end

  defp changed_path_context_keys do
    ["changed_paths", :changed_paths, "changed_files", :changed_files]
  end

  defp changed_path_payload_keys do
    ["changed_paths", :changed_paths, "changed_files", :changed_files, "files", :files]
  end

  defp first_present_value(map, keys) when is_map(map) do
    Enum.reduce_while(keys, :not_found, fn key, :not_found ->
      case Map.fetch(map, key) do
        {:ok, value} -> {:halt, {:ok, value}}
        :error -> {:cont, :not_found}
      end
    end)
  end

  defp first_present_value(_, _), do: :not_found

  defp decide(state) do
    source_sink = source_sink_verdict(state)
    {verdict, action, reason} = strongest_verdict(state.policy_verdict, source_sink)
    sanitized_text = sanitized_text(state.text, state.hits, state.quarantine, action, state.opts)

    %Decision{
      verdict: verdict,
      action: action,
      reason: reason,
      phase: state.context.phase,
      risk_level: state.risk,
      trust_level: state.context.trust_level,
      hits: state.hits,
      indicators: state.quarantine.indicators,
      sanitized_text: sanitized_text,
      content_hash: state.quarantine.content_hash,
      audit_metadata: audit_metadata(state, verdict, action)
    }
  end

  defp source_sink_verdict(%{
         repo_policy: %RepoDecision{verdict: :block} = decision
       }) do
    {:blocked, :block, decision.reason}
  end

  defp source_sink_verdict(%{
         repo_policy: %RepoDecision{verdict: :require_approval} = decision
       }) do
    {:confirm, :require_approval, decision.reason}
  end

  defp source_sink_verdict(%{
         repo_policy: {:error, reason}
       }) do
    {:blocked, :block, "Repo policy could not be compiled: #{inspect(reason)}"}
  end

  defp source_sink_verdict(%{
         context: %Context{trust_zone: :untrusted, phase: :tool_request}
       }) do
    {:blocked, :block, "Untrusted tool requests cannot execute privileged actions"}
  end

  defp source_sink_verdict(%{context: context, quarantine: %{verdict: :blocked}}) do
    blocked_quarantine_verdict(context)
  end

  defp source_sink_verdict(%{
         context: %Context{phase: :tool_result},
         quarantine: %{verdict: :suspicious}
       }) do
    {:confirm, :quarantine, "Tool result should be reviewed before model ingestion"}
  end

  defp source_sink_verdict(%{context: context, hits: [_ | _], opts: opts}) do
    if external_sensitive_block?(context, opts) do
      {:blocked, :block, "Sensitive content cannot cross into #{context.sink} without redaction"}
    else
      {:allowed, :redact, "Sensitive content redacted before boundary crossing"}
    end
  end

  defp source_sink_verdict(_), do: {:allowed, :allow, nil}

  defp blocked_quarantine_verdict(%Context{phase: :tool_result, sink: :model}) do
    {:confirm, :quarantine, "Tool result contains prompt-injection indicators"}
  end

  defp blocked_quarantine_verdict(_) do
    {:blocked, :block, "Content contains prompt-injection or exfiltration indicators"}
  end

  defp external_sensitive_block?(context, opts) do
    external_sink?(context.sink) and Keyword.get(opts, :on_sensitive, :block) == :block
  end

  defp strongest_verdict(:blocked, _), do: {:blocked, :block, "Policy blocked this action"}
  defp strongest_verdict(_, {:blocked, action, reason}), do: {:blocked, action, reason}

  defp strongest_verdict({:confirm, policy_reason}, {:confirm, action, source_reason}) do
    reason = Enum.join([policy_reason, source_reason], "; ")
    {{:confirm, reason}, action, source_reason}
  end

  defp strongest_verdict({:confirm, reason}, {:allowed, action, _}),
    do: {{:confirm, reason}, action, reason}

  defp strongest_verdict(:allowed, {:confirm, action, reason}),
    do: {{:confirm, reason}, action, reason}

  defp strongest_verdict(:allowed, {:allowed, action, reason}), do: {:allowed, action, reason}

  defp sanitized_text(nil, _, quarantine, _, _), do: quarantine.sanitized_text

  defp sanitized_text(text, hits, quarantine, action, opts) do
    redacted = redact_hits(text, hits, opts)

    cond do
      action == :quarantine ->
        Quarantine.sanitize(redacted)

      action == :redact ->
        redacted

      action == :block and hits != [] ->
        redacted

      action == :block and quarantine.indicators != [] ->
        Quarantine.sanitize(redacted)

      true ->
        text
    end
  end

  defp redact_hits(text, [], _), do: text
  defp redact_hits(text, hits, opts), do: Scanner.redact(text, hits, opts)

  defp external_sink?(sink), do: sink in @external_sinks

  defp audit_metadata(state, verdict, action) do
    %{
      phase: state.context.phase,
      actor: state.context.actor,
      identity: state.context.identity,
      origin: state.context.origin,
      sink: state.context.sink,
      tool: state.context.tool || action_from_payload(state.payload),
      mcp_server: state.context.mcp_server,
      resource_uri: state.context.resource_uri,
      trust_zone: state.context.trust_zone,
      trust_level: state.context.trust_level,
      risk_level: state.risk,
      verdict: audit_verdict(verdict),
      action: action,
      hit_count: length(state.hits),
      indicator_count: length(state.quarantine.indicators),
      indicator_ids: Enum.map(state.quarantine.indicators, & &1.id),
      content_hash: state.quarantine.content_hash,
      action_digest: action_digest(state, verdict)
    }
    |> put_repo_policy_metadata(state.repo_policy)
  end

  defp action_digest(state, {:confirm, _}) do
    Confirmation.action_digest(state.payload, state.context)
  end

  defp action_digest(_, _), do: nil

  defp action_from_payload(payload) when is_map(payload) do
    payload[:tool] || payload["tool"] || payload[:action] || payload["action"]
  end

  defp action_from_payload(_), do: nil

  defp audit_verdict({:confirm, _}), do: :confirm
  defp audit_verdict(verdict), do: verdict

  defp repo_policy_verdict(%RepoDecision{verdict: verdict}), do: verdict
  defp repo_policy_verdict({:error, _}), do: :block
  defp repo_policy_verdict(_), do: nil

  defp put_repo_policy_metadata(metadata, %RepoDecision{} = decision) do
    Map.merge(metadata, %{
      repo_policy_verdict: decision.verdict,
      repo_policy_rules: decision.matched_rule_ids,
      repo_unmatched_paths: decision.unmatched_paths
    })
  end

  defp put_repo_policy_metadata(metadata, {:error, reason}) do
    Map.merge(metadata, %{
      repo_policy_verdict: :block,
      repo_policy_rules: [],
      repo_unmatched_paths: [],
      repo_policy_error: inspect(reason)
    })
  end

  defp put_repo_policy_metadata(metadata, _), do: metadata

  defp emit_decision(%Decision{} = decision) do
    Telemetry.emit(
      [:sigil_guard, :runtime, :gate],
      %{system_time: System.system_time()},
      Map.take(decision.audit_metadata, [
        :phase,
        :actor,
        :identity,
        :origin,
        :sink,
        :tool,
        :mcp_server,
        :resource_uri,
        :trust_zone,
        :trust_level,
        :risk_level,
        :verdict,
        :action,
        :hit_count,
        :indicator_count,
        :indicator_ids,
        :content_hash,
        :action_digest,
        :runtime_input_error,
        :repo_policy_verdict,
        :repo_policy_rules,
        :repo_unmatched_paths,
        :repo_policy_error
      ])
    )
  end
end
