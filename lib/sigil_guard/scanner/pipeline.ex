defmodule SigilGuard.Scanner.Pipeline do
  @moduledoc """
  Deterministic staged scanner pipeline.

  Regex matching remains the first stage for compatibility with existing
  pattern bundles. Later stages validate candidate structure and attach
  deterministic confidence/signals so callers can distinguish a bare regex
  match from a higher-confidence secret finding.

  ## Stages

    * `:regex` - collect pattern candidates and byte offsets
    * `:validate` - reject structurally weak, boundary-ambiguous, placeholder, or low-entropy candidates
    * `:enrich` - add confidence and non-sensitive signal metadata
    * `:sort` - return hits in source order

  The pipeline is intentionally rule-based and local. It does not send content
  to an external classifier or probabilistic model.
  """

  alias SigilGuard.Patterns

  @typedoc "Non-sensitive evidence labels attached to enriched scanner hits."
  @type signal ::
          :assignment_context
          | :assignment_boundary
          | :credential_category
          | :high_entropy
          | :known_key_format
          | :long_value
          | :token_boundary
          | :uri_with_authority

  @typedoc "Internal regex candidate before validation and enrichment."
  @type candidate :: %{
          pattern: Patterns.compiled_pattern(),
          match: String.t(),
          offset: non_neg_integer(),
          length: non_neg_integer(),
          previous_byte: byte() | nil,
          next_byte: byte() | nil
        }

  @doc """
  Run the staged scanner pipeline and return enriched hits.

  Options:

    * `:validate` - set to `false` to keep all regex candidates.
    * `:min_confidence` - discard hits below this score. Defaults to `0.0`.
    * `:generic_secret_min_length` - generic secret value minimum length. Defaults to `10`.
    * `:generic_secret_min_entropy` - generic secret Shannon entropy floor. Defaults to `2.8`.
    * `:token_min_entropy` - bearer/API token Shannon entropy floor. Defaults to `3.0`.
  """
  @spec scan(String.t(), [Patterns.compiled_pattern()], keyword()) :: [Patterns.scan_hit()]
  def scan(text, patterns, opts \\ []) when is_binary(text) and is_list(patterns) do
    min_confidence = confidence_floor(opts, :min_confidence, 0.0)

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
        {previous_byte, next_byte} = boundary_bytes(text, offset, length)

        %{
          pattern: pattern,
          match: binary_part(text, offset, length),
          offset: offset,
          length: length,
          previous_byte: previous_byte,
          next_byte: next_byte
        }
      end)
    end)
  end

  defp valid_candidate?(candidate, opts) do
    not validation_enabled?(opts) or structurally_valid?(candidate, opts)
  end

  defp structurally_valid?(%{pattern: %{name: "aws_access_key"}, match: match} = candidate, _) do
    Regex.match?(~r/\A(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\z/, match) and
      token_boundary?(candidate, &ascii_alphanumeric_byte?/1)
  end

  defp structurally_valid?(%{pattern: %{name: "bearer_token"}, match: match} = candidate, opts) do
    label_boundary?(candidate) and token_boundary?(candidate, &bearer_token_byte?/1) and
      match
      |> bearer_value()
      |> token_like?(20, entropy_option(opts, :token_min_entropy, 3.0))
  end

  defp structurally_valid?(%{pattern: %{name: "database_uri"}, match: match} = candidate, _) do
    label_boundary?(candidate) and String.contains?(match, "://") and String.contains?(match, ":") and
      String.ends_with?(match, "@")
  end

  defp structurally_valid?(%{pattern: %{name: "private_key"}, match: match}, _) do
    String.starts_with?(match, "-----BEGIN ") and String.ends_with?(match, "PRIVATE KEY-----")
  end

  defp structurally_valid?(%{pattern: %{name: "generic_api_key"}, match: match} = candidate, opts) do
    assignment_boundary?(candidate) and
      match
      |> assignment_value()
      |> token_like?(20, entropy_option(opts, :token_min_entropy, 3.0))
  end

  defp structurally_valid?(%{pattern: %{name: "generic_secret"}, match: match} = candidate, opts) do
    value = assignment_value(match)

    assignment_boundary?(candidate) and
      secret_like?(
        value,
        positive_integer_option(opts, :generic_secret_min_length, 10),
        entropy_option(opts, :generic_secret_min_entropy, 2.8)
      )
  end

  defp structurally_valid?(_, _), do: true

  defp enrich_hit(candidate, opts) do
    signals = signals(candidate)
    validated? = validation_enabled?(opts)

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
      assignment_boundary?(candidate) && :assignment_boundary,
      high_entropy?(value) && :high_entropy,
      byte_size(value) >= 20 && :long_value,
      token_boundary_signal?(candidate) && :token_boundary,
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
  defp signal_bonus(:assignment_boundary), do: 0.04
  defp signal_bonus(:high_entropy), do: 0.08
  defp signal_bonus(:long_value), do: 0.04
  defp signal_bonus(:credential_category), do: 0.03
  defp signal_bonus(:token_boundary), do: 0.03
  defp signal_bonus(:uri_with_authority), do: 0.07

  defp credential_category?(%{pattern: %{category: "credential"}}), do: true
  defp credential_category?(_), do: false

  defp known_key_format?(%{pattern: %{name: name}}) do
    name in ["aws_access_key", "private_key", "bearer_token"]
  end

  defp assignment_context?(match),
    do: String.contains?(match, "=") or String.contains?(match, ":")

  defp assignment_boundary?(%{pattern: %{name: name}} = candidate)
       when name in ["generic_api_key", "generic_secret"] do
    label_boundary?(candidate)
  end

  defp assignment_boundary?(%{pattern: %{name: "database_uri"}} = candidate) do
    label_boundary?(candidate)
  end

  defp assignment_boundary?(_), do: false

  defp token_boundary_signal?(%{pattern: %{name: "aws_access_key"}} = candidate) do
    token_boundary?(candidate, &ascii_alphanumeric_byte?/1)
  end

  defp token_boundary_signal?(%{pattern: %{name: "bearer_token"}} = candidate) do
    token_boundary?(candidate, &bearer_token_byte?/1)
  end

  defp token_boundary_signal?(_), do: false

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

  defp boundary_bytes(text, offset, length) do
    {previous_byte(text, offset), next_byte(text, offset + length)}
  end

  defp previous_byte(_, 0), do: nil
  defp previous_byte(text, offset), do: :binary.at(text, offset - 1)

  defp next_byte(text, offset) when offset < byte_size(text), do: :binary.at(text, offset)
  defp next_byte(_, _), do: nil

  defp label_boundary?(%{previous_byte: byte}), do: boundary_byte?(byte)

  defp token_boundary?(%{previous_byte: previous_byte, next_byte: next_byte}, byte?) do
    boundary_for?(previous_byte, byte?) and boundary_for?(next_byte, byte?)
  end

  defp boundary_for?(nil, _), do: true
  defp boundary_for?(byte, byte?), do: not byte?.(byte)

  defp boundary_byte?(nil), do: true

  defp boundary_byte?(byte) do
    not ascii_alphanumeric_byte?(byte) and byte != ?_ and byte != ?-
  end

  defp ascii_alphanumeric_byte?(byte) do
    (byte >= ?a and byte <= ?z) or (byte >= ?A and byte <= ?Z) or (byte >= ?0 and byte <= ?9)
  end

  defp bearer_token_byte?(byte) do
    ascii_alphanumeric_byte?(byte) or byte in [?., ?_, ?~, ?+, ?/, ?=, ?-]
  end

  defp token_like?(value, min_length, min_entropy) do
    secret_like?(value, min_length, min_entropy)
  end

  defp secret_like?(value, min_length, min_entropy) do
    value = String.trim(value)

    byte_size(value) >= min_length and character_diversity(value) >= 4 and
      shannon_entropy(value) >= min_entropy and not weak_secret_value?(value)
  end

  defp weak_secret_value?(value) do
    normalized =
      value
      |> String.downcase()
      |> String.trim(~s('"`))

    placeholder_value?(normalized) or repeated_value?(normalized)
  end

  defp placeholder_value?(value) do
    Regex.match?(
      ~r/\A(?:change[-_]?me|placeholder|dummy|example|sample|test(?:ing)?|password|secret|token|credential|your[-_]?[a-z0-9_-]+)(?:[0-9_-]*)\z/,
      value
    )
  end

  defp repeated_value?(value) do
    Regex.match?(~r/\A(.{1,4})\1{2,}\z/s, value)
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

  defp validation_enabled?(opts), do: Keyword.get(opts, :validate, true) != false

  defp confidence_floor(opts, key, default) do
    case Keyword.get(opts, key, default) do
      value when is_number(value) and value >= 0.0 and value <= 1.0 -> value
      _ -> default
    end
  end

  defp positive_integer_option(opts, key, default) do
    case Keyword.get(opts, key, default) do
      value when is_integer(value) and value > 0 -> value
      _ -> default
    end
  end

  defp entropy_option(opts, key, default) do
    case Keyword.get(opts, key, default) do
      value when is_number(value) and value >= 0.0 -> value
      _ -> default
    end
  end
end
