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
    patterns = Keyword.get_lazy(opts, :patterns, &Patterns.built_in/0)

    Telemetry.span([:sigil_guard, :scan], %{patterns_checked: length(patterns)}, fn ->
      hits = do_scan(text, patterns, opts)

      result =
        if hits == [] do
          {:ok, text}
        else
          {:hit, hits}
        end

      {result, %{hit_count: length(hits), patterns_checked: length(patterns)}}
    end)
  end

  @doc """
  Replace all matched regions in `text` with their replacement hints.

  Hits are applied in reverse offset order to preserve positions.

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
    default = Keyword.get(opts, :default_replacement, "[REDACTED]")

    hits
    |> Enum.sort_by(& &1.offset, :desc)
    |> Enum.reduce(text, fn hit, acc ->
      replacement = hit.replacement_hint || default
      prefix = binary_part(acc, 0, hit.offset)
      suffix_start = hit.offset + hit.length
      suffix = binary_part(acc, suffix_start, byte_size(acc) - suffix_start)
      prefix <> replacement <> suffix
    end)
  end

  @doc """
  Scan and redact in a single pass. Returns the redacted text.
  """
  @spec scan_and_redact(String.t(), keyword()) :: String.t()
  def scan_and_redact(text, opts \\ []) do
    case scan(text, opts) do
      {:ok, clean_text} -> clean_text
      {:hit, hits} -> redact(text, hits, opts)
    end
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
end
