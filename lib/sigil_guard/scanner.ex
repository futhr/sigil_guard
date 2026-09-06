defmodule SigilGuard.Scanner do
  @moduledoc """
  Sensitivity scanning and redaction for text content.

  Scans strings for sensitive content (credentials, API keys, PII) using
  a staged deterministic pipeline over compiled regex patterns. The pipeline
  validates and enriches regex candidates with confidence and signal metadata,
  then provides redaction with configurable replacement hints.

  ## Pipeline Extensions

  Pass `pipeline: MyPipeline` to use a module that exports `scan/3`.
  The module receives `(text, patterns, opts)` and must return scan hits.
  """

  alias SigilGuard.Patterns
  alias SigilGuard.Scanner.Pipeline
  alias SigilGuard.Telemetry

  @doc """
  Scan text for sensitive content using the given patterns.

  Returns `{:ok, text}` if no hits are found, or `{:hit, hits}` with a list
  of `SigilGuard.Patterns.scan_hit()` structs describing each match.

  ## Options

    * `:max_input_bytes` — binary-data budget (default: 1 MiB); exhaustion raises `ArgumentError`.
    * `:patterns` — compiled patterns to use. Defaults to built-in patterns.
    * `:pipeline` — `:staged` (default), `:regex`, or a module with `scan/3`.
    * `:validate` — set to `false` to keep all regex candidates in staged mode.
    * `:min_confidence` — discard staged hits below this score. Defaults to `0.0`.

  ## Examples

      iex> SigilGuard.Scanner.scan("safe text")
      {:ok, "safe text"}

      iex> {:hit, hits} =
      ...>   SigilGuard.Scanner.scan("Authorization: Bearer sk-abc123def456ghi789jkl012mno345")
      ...>
      ...> length(hits) > 0
      true

  """
  @spec scan(String.t(), keyword()) :: {:ok, String.t()} | {:hit, [Patterns.scan_hit()]}
  def scan(text, opts \\ []) do
    validate_options!(opts)

    if SigilGuard.Limits.check(text, opts) != :ok,
      do: raise(ArgumentError, "scanner input budget exceeded")

    patterns = Keyword.get_lazy(opts, :patterns, &Patterns.built_in/0)
    telemetry_metadata = telemetry_metadata(patterns, opts)

    Telemetry.span([:sigil_guard, :scan], telemetry_metadata, fn ->
      hits =
        text
        |> do_scan(patterns, opts)
        |> validate_hits!(text)

      result =
        if hits == [] do
          {:ok, text}
        else
          {:hit, hits}
        end

      {result, Map.put(telemetry_metadata, :hit_count, length(hits))}
    end)
  end

  @doc """
  Replace all matched regions in `text` with their replacement hints.

  Overlapping spans are merged against the original bytes. The leftmost,
  longest hit supplies the replacement; ties sort by replacement text.

  ## Options

    * `:default_replacement` — fallback replacement when a hit has no
      `replacement_hint`. Default: `"[REDACTED]"`

  ## Examples

      iex> hits = [
      ...>   %{offset: 0, length: 20, match: "AKIAIOSFODNN7EXAMPLE", replacement_hint: "[AWS_KEY]"}
      ...> ]
      ...>
      ...> SigilGuard.Scanner.redact("AKIAIOSFODNN7EXAMPLE secret", hits)
      "[AWS_KEY] secret"

  """
  @spec redact(String.t(), [Patterns.scan_hit()], keyword()) :: String.t()
  def redact(text, hits, opts \\ []) do
    validate_options!(opts)
    default = Keyword.get(opts, :default_replacement, "[REDACTED]")

    spans =
      hits
      |> Enum.map(&redaction_span!(&1, text, default))
      |> Enum.sort()
      |> Enum.reduce([], &merge_span/2)
      |> Enum.reverse()

    {parts, position} =
      Enum.reduce(spans, {[], 0}, fn {offset, negative_end, replacement}, {parts, position} ->
        prefix = binary_part(text, position, offset - position)
        {[parts, prefix, replacement], -negative_end}
      end)

    IO.iodata_to_binary([parts, binary_part(text, position, byte_size(text) - position)])
  end

  defp redaction_span!(%{offset: offset, length: length} = hit, text, default)
       when is_integer(offset) and offset >= 0 and is_integer(length) and length > 0 and
              offset + length <= byte_size(text) do
    replacement = Map.get(hit, :replacement_hint) || default
    if not is_binary(replacement), do: raise(ArgumentError, "replacement must be a binary")
    {offset, -(offset + length), replacement}
  end

  defp redaction_span!(_, _, _), do: raise(ArgumentError, "invalid redaction span")

  defp merge_span({offset, ending, _}, [{start, previous_end, replacement} | rest])
       when offset < -previous_end do
    [{start, min(ending, previous_end), replacement} | rest]
  end

  defp merge_span(span, spans), do: [span | spans]

  @doc """
  Scan and redact in a single pass. Returns the redacted text.
  """
  @spec scan_and_redact(String.t(), keyword()) :: String.t()
  def scan_and_redact(text, opts \\ []) do
    validate_options!(opts)

    case scan(text, opts) do
      {:ok, clean_text} -> clean_text
      {:hit, hits} -> redact(text, hits, opts)
    end
  end

  defp validate_options!(opts) do
    if Keyword.keyword?(opts),
      do: :ok,
      else: raise(ArgumentError, "options must be a keyword list")
  end

  defp do_scan(text, patterns, opts) do
    case Keyword.get(opts, :pipeline, :staged) do
      :staged ->
        Pipeline.scan(text, patterns, opts)

      :regex ->
        Pipeline.regex_scan(text, patterns)

      module when is_atom(module) ->
        Code.ensure_loaded(module)

        if function_exported?(module, :scan, 3) do
          module.scan(text, patterns, opts)
        else
          raise ArgumentError, "scanner pipeline module must export scan/3"
        end

      other ->
        raise ArgumentError, "invalid scanner pipeline #{inspect(other)}"
    end
  end

  defp validate_hits!(hits, text) when is_list(hits) do
    if Enum.all?(hits, &valid_hit?(&1, text)) do
      hits
    else
      raise ArgumentError, "scanner pipeline must return valid scan hits"
    end
  end

  defp validate_hits!(_, _), do: raise(ArgumentError, "scanner pipeline must return a hit list")

  defp valid_hit?(
         %{
           name: name,
           category: category,
           severity: severity,
           match: match,
           offset: offset,
           length: length
         } = hit,
         text
       )
       when is_binary(name) and severity in [:low, :medium, :high] and
              is_binary(match) and is_integer(offset) and is_integer(length) and
              offset >= 0 and length >= 0 and offset + length <= byte_size(text) do
    valid_category?(category) and valid_replacement_hint?(Map.get(hit, :replacement_hint))
  end

  defp valid_hit?(_, _), do: false

  # Built-in patterns emit the closed :secret/:injection/:poisoning atoms;
  # custom/compatibility-bundle patterns may carry a free-form string category.
  defp valid_category?(category), do: is_atom(category) or is_binary(category)

  defp valid_replacement_hint?(hint), do: is_binary(hint) or is_nil(hint)

  defp telemetry_metadata(patterns, opts) do
    %{
      patterns_checked: length(patterns),
      pipeline: pipeline_name(Keyword.get(opts, :pipeline, :staged)),
      scanner_validate: Keyword.get(opts, :validate, true) != false
    }
  end

  defp pipeline_name(module) when is_atom(module), do: module
  defp pipeline_name(other), do: inspect(other)
end
