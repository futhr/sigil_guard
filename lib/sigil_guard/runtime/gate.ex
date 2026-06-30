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
    text = Context.text(payload)
    action = Context.action_name(context, payload)
    hits = scan_hits(text, opts)
    quarantine = Quarantine.inspect(text, context, opts)
    risk = risk_level(action, context, hits, quarantine, opts)

    policy_verdict =
      Policy.evaluate(action, context.trust_level, Keyword.put(opts, :risk_level, risk))

    decision =
      decide(%{
        payload: payload,
        text: text,
        context: context,
        hits: hits,
        quarantine: quarantine,
        risk: risk,
        policy_verdict: policy_verdict,
        opts: opts
      })

    emit_decision(decision)
    decision
  end

  defp scan_hits(nil, _), do: []

  defp scan_hits(text, opts) do
    case Scanner.scan(text, opts) do
      {:ok, _} -> []
      {:hit, hits} -> hits
    end
  end

  defp risk_level(action, context, hits, quarantine, opts) do
    Keyword.get_lazy(opts, :risk_level, fn ->
      cond do
        quarantine.verdict == :blocked -> :high
        quarantine.verdict == :suspicious -> :medium
        Enum.any?(hits, &(&1.severity == :high)) and external_sink?(context.sink) -> :high
        hits != [] -> :medium
        true -> Policy.classify_risk(action, opts)
      end
    end)
  end

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

  defp sanitized_text(text, hits, _, action, opts)
       when action in [:redact, :quarantine] do
    text
    |> Scanner.redact(hits, opts)
    |> then(fn redacted ->
      if action == :quarantine, do: Quarantine.sanitize(redacted), else: redacted
    end)
  end

  defp sanitized_text(text, _, _, _, _), do: text

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

  defp emit_decision(%Decision{} = decision) do
    Telemetry.emit(
      [:sigil_guard, :runtime, :gate],
      %{system_time: System.system_time()},
      Map.take(decision.audit_metadata, [
        :phase,
        :origin,
        :sink,
        :tool,
        :trust_zone,
        :trust_level,
        :risk_level,
        :verdict,
        :action,
        :hit_count,
        :indicator_count
      ])
    )
  end
end
