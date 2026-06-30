defmodule SigilGuard.Quarantine do
  @moduledoc """
  Deterministic quarantine checks for untrusted tool and resource content.

  This is intentionally small and local: it catches common prompt-injection
  and tool-poisoning indicators before content is passed onward to a model
  or privileged tool. It is not a replacement for policy; it produces
  evidence for the runtime gate.
  """

  alias SigilGuard.Context

  @type verdict :: :safe | :suspicious | :blocked

  @type result :: %{
          verdict: verdict(),
          indicators: [map()],
          content_hash: String.t(),
          sanitized_text: String.t() | nil
        }

  @indicators [
    %{
      id: :ignore_instructions,
      severity: :high,
      prefilter: ["instruction"],
      pattern: ~r/ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/i
    },
    %{
      id: :exfiltration_request,
      severity: :high,
      prefilter: ["exfiltrate", "send", "upload", "post"],
      pattern: ~r/(exfiltrate|send|upload|post).{0,40}(secret|token|key|credential|password)/i
    },
    %{
      id: :system_prompt_probe,
      severity: :medium,
      prefilter: ["system", "developer"],
      pattern: ~r/(system|developer)\s+(prompt|message|instructions?)/i
    },
    %{
      id: :model_extraction_request,
      severity: :high,
      prefilter: ["reveal", "dump", "print", "repeat", "extract", "send"],
      pattern:
        ~r/(reveal|dump|print|repeat|extract|send).{0,60}(system prompt|developer message|hidden instructions?|training data|memorized data)/i
    },
    %{
      id: :credential_harvest_instruction,
      severity: :high,
      prefilter: ["ask", "prompt", "request", "collect"],
      pattern:
        ~r/(ask|prompt|request|collect).{0,50}(password|api[_\s-]?key|token|credential|secret)/i
    },
    %{
      id: :tool_poisoning_directive,
      severity: :medium,
      prefilter: ["when", "before", "after"],
      pattern:
        ~r/(when|before|after)\s+(using|calling|invoking).{0,50}(this\s+)?(tool|function|connector).{0,80}(ignore|override|prefer|follow|use)/i
    },
    %{
      id: :hidden_html_instruction,
      severity: :medium,
      prefilter: ["<!--", "display", "visibility", "<script"],
      pattern: ~r/(<!--|display\s*:\s*none|visibility\s*:\s*hidden|<script\b)/i
    }
  ]

  @prefilter_pattern ~r/(instruction|exfiltrate|send|upload|post|system|developer|reveal|dump|print|repeat|extract|ask|prompt|request|collect|when|before|after|<!--|display|visibility|<script)/i

  @doc """
  Inspect text for deterministic quarantine indicators.
  """
  @spec inspect(String.t() | nil, Context.t() | map() | keyword(), keyword()) :: result()
  def inspect(text, context \\ %Context{}, opts \\ [])

  def inspect(text, context, opts) when is_binary(text) do
    context = Context.new(context)
    active_indicators = indicators_for(text)
    indicators = find_indicators(text, active_indicators)
    verdict = verdict(indicators, context, opts)

    %{
      verdict: verdict,
      indicators: indicators,
      content_hash: hash(text),
      sanitized_text: sanitized_text(text, active_indicators, indicators)
    }
  end

  def inspect(_, _, _) do
    %{
      verdict: :safe,
      indicators: [],
      content_hash: hash(""),
      sanitized_text: nil
    }
  end

  @doc """
  Replace deterministic quarantine indicator spans with a neutral marker.
  """
  @spec sanitize(String.t()) :: String.t()
  def sanitize(text) when is_binary(text) do
    text
    |> indicators_for()
    |> sanitize(text)
  end

  defp sanitize(indicators, text) do
    indicators
    |> Enum.reduce(text, fn indicator, acc ->
      Regex.replace(indicator.pattern, acc, "[QUARANTINED]")
    end)
  end

  defp find_indicators(text, active_indicators) do
    Enum.flat_map(active_indicators, fn indicator ->
      if Regex.match?(indicator.pattern, text) do
        [Map.take(indicator, [:id, :severity])]
      else
        []
      end
    end)
  end

  defp sanitized_text(text, _, []), do: text
  defp sanitized_text(text, active_indicators, _), do: sanitize(active_indicators, text)

  defp indicators_for(text) do
    if Regex.match?(@prefilter_pattern, text) do
      lowercase = String.downcase(text)

      Enum.filter(@indicators, fn indicator ->
        contains_any?(lowercase, indicator.prefilter)
      end)
    else
      []
    end
  end

  defp contains_any?(text, tokens) do
    Enum.any?(tokens, fn token ->
      :binary.match(text, token) != :nomatch
    end)
  end

  defp verdict([], _, _), do: :safe

  defp verdict(indicators, %Context{phase: :tool_result, sink: :model}, opts) do
    if Keyword.get(opts, :strict_quarantine, false) or high_severity?(indicators) do
      :blocked
    else
      :suspicious
    end
  end

  defp verdict(indicators, _, _) do
    if high_severity?(indicators), do: :blocked, else: :suspicious
  end

  defp high_severity?(indicators), do: Enum.any?(indicators, &(&1.severity == :high))

  defp hash(text) do
    :sha256
    |> :crypto.hash(text)
    |> Base.encode16(case: :lower)
  end
end
