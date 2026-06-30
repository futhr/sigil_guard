defmodule SigilGuard.Scanner.Pipeline do
  @moduledoc """
  Deterministic staged scanner pipeline.

  Regex matching remains the first stage for compatibility with existing
  pattern bundles. Later stages validate candidate structure and attach
  deterministic confidence/signals so callers can distinguish a bare regex
  match from a higher-confidence secret finding.

  ## Stages

    * `:regex` - collect pattern candidates and byte offsets
    * `:validate` - reject structurally weak generic candidates
    * `:enrich` - add confidence and non-sensitive signal metadata
    * `:sort` - return hits in source order

  The pipeline is intentionally rule-based and local. It does not send content
  to an external classifier or probabilistic model.
  """

  alias SigilGuard.Patterns

  @typedoc "Non-sensitive evidence labels attached to enriched scanner hits."
  @type signal ::
          :assignment_context
          | :credential_category
          | :high_entropy
          | :known_key_format
          | :long_value
          | :uri_with_authority

  @typedoc "Internal regex candidate before validation and enrichment."
  @type candidate :: %{
          pattern: Patterns.compiled_pattern(),
          match: String.t(),
          offset: non_neg_integer(),
          length: non_neg_integer()
        }

  @doc """
  Run the staged scanner pipeline and return enriched hits.

  Options:

    * `:validate` - set to `false` to keep all regex candidates.
    * `:min_confidence` - discard hits below this score. Defaults to `0.0`.
  """
  @spec scan(String.t(), [Patterns.compiled_pattern()], keyword()) :: [Patterns.scan_hit()]
  def scan(text, patterns, opts \\ []) when is_binary(text) and is_list(patterns) do
    min_confidence = Keyword.get(opts, :min_confidence, 0.0)

    text
    |> regex_candidates(patterns)
    |> Enum.filter(&valid_candidate?(&1, opts))
    |> Enum.map(&enrich_hit(&1, opts))
    |> Enum.filter(&(&1.confidence >= min_confidence))
    |> Enum.sort_by(& &1.offset)
  end

  @doc """
  Run only the regex candidate stage and return legacy hit maps.
  """
  @spec regex_scan(String.t(), [Patterns.compiled_pattern()]) :: [Patterns.scan_hit()]
  def regex_scan(text, patterns) when is_binary(text) and is_list(patterns) do
    text
    |> regex_candidates(patterns)
    |> Enum.map(&legacy_hit/1)
    |> Enum.sort_by(& &1.offset)
  end

  @doc """
  Return raw regex candidates before validation or enrichment.
  """
  @spec regex_candidates(String.t(), [Patterns.compiled_pattern()]) :: [candidate()]
  def regex_candidates(text, patterns) when is_binary(text) and is_list(patterns) do
    Enum.flat_map(patterns, fn pattern ->
      pattern.regex
      |> Regex.scan(text, return: :index)
      |> Enum.map(fn [{offset, length} | _] ->
        %{
          pattern: pattern,
          match: binary_part(text, offset, length),
          offset: offset,
          length: length
        }
      end)
    end)
  end

  defp valid_candidate?(candidate, opts) do
    not Keyword.get(opts, :validate, true) or structurally_valid?(candidate)
  end

  defp structurally_valid?(%{pattern: %{name: "aws_access_key"}, match: match}) do
    Regex.match?(~r/\A(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\z/, match)
  end

  defp structurally_valid?(%{pattern: %{name: "bearer_token"}, match: match}) do
    match
    |> bearer_value()
    |> token_like?(20)
  end

  defp structurally_valid?(%{pattern: %{name: "database_uri"}, match: match}) do
    String.contains?(match, "://") and String.contains?(match, ":") and
      String.ends_with?(match, "@")
  end

  defp structurally_valid?(%{pattern: %{name: "private_key"}, match: match}) do
    String.starts_with?(match, "-----BEGIN ") and String.ends_with?(match, "PRIVATE KEY-----")
  end

  defp structurally_valid?(%{pattern: %{name: "generic_api_key"}, match: match}) do
    match
    |> assignment_value()
    |> token_like?(20)
  end

  defp structurally_valid?(%{pattern: %{name: "generic_secret"}, match: match}) do
    value = assignment_value(match)
    byte_size(value) >= 8 and character_diversity(value) >= 3
  end

  defp structurally_valid?(_), do: true

  defp enrich_hit(candidate, opts) do
    signals = signals(candidate)
    validated? = Keyword.get(opts, :validate, true)

    candidate
    |> legacy_hit()
    |> Map.merge(%{
      confidence: confidence(candidate, signals),
      signals: signals,
      stage: if(validated?, do: :validated, else: :enriched),
      validated: validated?
    })
  end

  defp legacy_hit(%{pattern: pattern, match: match, offset: offset, length: length}) do
    %{
      name: pattern.name,
      category: pattern.category,
      severity: pattern.severity,
      match: match,
      offset: offset,
      length: length,
      replacement_hint: pattern.replacement_hint
    }
  end

  defp signals(candidate) do
    value = secret_value(candidate.match, candidate.pattern.name)

    [
      credential_category?(candidate) && :credential_category,
      known_key_format?(candidate) && :known_key_format,
      assignment_context?(candidate.match) && :assignment_context,
      high_entropy?(value) && :high_entropy,
      byte_size(value) >= 20 && :long_value,
      uri_authority?(candidate) && :uri_with_authority
    ]
    |> Enum.filter(& &1)
  end

  defp confidence(candidate, signals) do
    candidate.pattern.name
    |> base_confidence()
    |> add_signal_bonus(signals)
    |> min(0.99)
    |> Float.round(2)
  end

  defp base_confidence("aws_access_key"), do: 0.91
  defp base_confidence("private_key"), do: 0.9
  defp base_confidence("database_uri"), do: 0.86
  defp base_confidence("bearer_token"), do: 0.82
  defp base_confidence("generic_api_key"), do: 0.74
  defp base_confidence("generic_secret"), do: 0.6
  defp base_confidence(_), do: 0.5

  defp add_signal_bonus(score, signals) do
    Enum.reduce(signals, score, fn signal, acc -> acc + signal_bonus(signal) end)
  end

  defp signal_bonus(:known_key_format), do: 0.08
  defp signal_bonus(:assignment_context), do: 0.08
  defp signal_bonus(:high_entropy), do: 0.08
  defp signal_bonus(:long_value), do: 0.04
  defp signal_bonus(:credential_category), do: 0.03
  defp signal_bonus(:uri_with_authority), do: 0.07

  defp credential_category?(%{pattern: %{category: "credential"}}), do: true
  defp credential_category?(_), do: false

  defp known_key_format?(%{pattern: %{name: name}}) do
    name in ["aws_access_key", "private_key", "bearer_token"]
  end

  defp assignment_context?(match),
    do: String.contains?(match, "=") or String.contains?(match, ":")

  defp high_entropy?(value), do: shannon_entropy(value) >= 3.0

  defp uri_authority?(%{pattern: %{name: "database_uri"}, match: match}) do
    String.contains?(match, "://") and String.ends_with?(match, "@")
  end

  defp uri_authority?(_), do: false

  defp secret_value(match, "bearer_token"), do: bearer_value(match)

  defp secret_value(match, pattern_name)
       when pattern_name in ["generic_api_key", "generic_secret"] do
    assignment_value(match)
  end

  defp secret_value(match, _), do: match

  defp bearer_value(match) do
    if byte_size(match) > 6 and String.downcase(binary_part(match, 0, 6)) == "bearer" do
      match
      |> binary_part(6, byte_size(match) - 6)
      |> String.trim_leading()
    else
      match
    end
  end

  defp assignment_value(match) do
    case :binary.match(match, ["=", ":"]) do
      {offset, 1} ->
        match
        |> binary_part(offset + 1, byte_size(match) - offset - 1)
        |> String.trim_leading()
        |> trim_leading_quote()
        |> take_until_terminator()

      :nomatch ->
        match
    end
  end

  defp trim_leading_quote(<<?', rest::binary>>), do: rest
  defp trim_leading_quote(<<?", rest::binary>>), do: rest
  defp trim_leading_quote(value), do: value

  defp take_until_terminator(value) do
    case :binary.match(value, [" ", "\t", "\n", "\r", "'", "\""]) do
      {offset, _} -> binary_part(value, 0, offset)
      :nomatch -> value
    end
  end

  defp token_like?(value, min_length) do
    byte_size(value) >= min_length and character_diversity(value) >= 3
  end

  defp character_diversity(""), do: 0

  defp character_diversity(value) do
    value
    |> :binary.bin_to_list()
    |> MapSet.new()
    |> MapSet.size()
  end

  defp shannon_entropy(""), do: 0.0

  defp shannon_entropy(value) do
    bytes = :binary.bin_to_list(value)
    length = length(bytes)

    bytes
    |> Enum.frequencies()
    |> Enum.reduce(0.0, fn {_, count}, acc ->
      probability = count / length
      acc - probability * :math.log2(probability)
    end)
  end
end
