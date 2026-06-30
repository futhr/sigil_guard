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
      pattern: ~r/ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/i
    },
    %{
      id: :exfiltration_request,
      severity: :high,
      pattern: ~r/(exfiltrate|send|upload|post).{0,40}(secret|token|key|credential|password)/i
    },
    %{
      id: :system_prompt_probe,
      severity: :medium,
      pattern: ~r/(system|developer)\s+(prompt|message|instructions?)/i
    },
    %{
      id: :hidden_html_instruction,
      severity: :medium,
      pattern: ~r/(<!--|display\s*:\s*none|visibility\s*:\s*hidden|<script\b)/i
    }
  ]

  @doc """
  Inspect text for deterministic quarantine indicators.
  """
  @spec inspect(String.t() | nil, Context.t() | map() | keyword(), keyword()) :: result()
  def inspect(text, context \\ %Context{}, opts \\ [])

  def inspect(text, context, opts) when is_binary(text) do
    context = Context.new(context)
    indicators = find_indicators(text)
    verdict = verdict(indicators, context, opts)

    %{
      verdict: verdict,
      indicators: indicators,
      content_hash: hash(text),
      sanitized_text: sanitize(text)
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
    Enum.reduce(@indicators, text, fn indicator, acc ->
      Regex.replace(indicator.pattern, acc, "[QUARANTINED]")
    end)
  end

  defp find_indicators(text) do
    Enum.flat_map(@indicators, fn indicator ->
      if Regex.match?(indicator.pattern, text) do
        [Map.take(indicator, [:id, :severity])]
      else
        []
      end
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
