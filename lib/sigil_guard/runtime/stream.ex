defmodule SigilGuard.Runtime.Stream do
  @moduledoc """
  Chunk-safe sanitizer for streaming runtime output.

  Streaming output can split credentials or prompt-injection phrases across
  chunk boundaries. This module keeps a configurable trailing holdback window,
  evaluates each buffered boundary crossing with `SigilGuard.Runtime.Gate`,
  and only emits content outside that window and any incomplete candidate.
  Unknown custom regex widths, custom indicators and custom pipelines retain
  the whole message until `finish/1`. Pending bytes default to a 1 MiB cap;
  `:max_stream_bytes` changes that cap. Exceeding it fails closed.

  If the gate blocks or requires confirmation, no new content is emitted and
  the stream is marked halted. Callers can inspect the returned decision to
  decide whether to drop, quarantine, or request approval.
  """

  alias SigilGuard.Context
  alias SigilGuard.Decision
  alias SigilGuard.Patterns
  alias SigilGuard.Runtime.Gate
  alias SigilGuard.Scanner

  @default_window_bytes 256
  @default_max_pending_bytes 1_048_576
  @unbounded_prefix ~r/api[_-]?key|bearer|postgres:\/\/|mysql:\/\/|mongodb:\/\/|secret|password|token|ignore|system|developer|when|before|after|display|visibility/i

  @type t :: %__MODULE__{
          context: Context.t(),
          opts: keyword(),
          pending: String.t(),
          window_bytes: pos_integer(),
          halted?: boolean(),
          decision: Decision.t() | nil
        }

  defstruct context: %Context{},
            opts: [],
            pending: "",
            window_bytes: @default_window_bytes,
            halted?: false,
            decision: nil

  @doc """
  Start a stream sanitizer for a labeled boundary.

  Options are passed through to `SigilGuard.Runtime.Gate.evaluate/3`.
  `:stream_window_bytes` controls the trailing holdback window and defaults
  to `#{@default_window_bytes}` bytes. Invalid window values fall back to the
  default so stream checks keep a conservative holdback. Options must be a
  keyword list. `:patterns` must contain compiled regex maps with positive
  integer width hints when supplied; invalid configuration raises `ArgumentError`.
  """
  @spec new(Context.t() | map() | keyword(), keyword()) :: t()
  def new(context \\ %Context{}, opts \\ []) do
    validate_options!(opts)

    %__MODULE__{
      context: Context.new(context),
      opts: opts,
      window_bytes: stream_window_bytes(opts)
    }
  end

  @doc """
  Push one output chunk through the sanitizer.

  Returns `{stream, decision, emitted_chunk}`. `emitted_chunk` is empty when
  the held-back content is not yet safe to release, or when the gate blocks
  or requires confirmation.
  """
  @spec push(t(), String.t()) :: {t(), Decision.t(), String.t()}
  def push(%__MODULE__{halted?: true, decision: %Decision{} = decision} = stream, chunk)
      when is_binary(chunk) do
    {stream, decision, ""}
  end

  def push(%__MODULE__{} = stream, chunk) when is_binary(chunk) do
    combined = stream.pending <> chunk
    limit = Keyword.get(stream.opts, :max_stream_bytes, @default_max_pending_bytes)

    if not is_integer(limit) or limit <= 0 or byte_size(combined) > limit do
      halt(stream, "stream capacity exceeded")
    else
      push_validated(stream, combined, :unicode.characters_to_binary(combined))
    end
  end

  defp push_validated(stream, _, {:error, _, _}), do: halt(stream, "invalid UTF-8")

  defp push_validated(stream, combined, {:incomplete, valid, _}),
    do: evaluate_chunk(stream, combined, valid)

  defp push_validated(stream, combined, valid), do: evaluate_chunk(stream, combined, valid)

  defp evaluate_chunk(stream, combined, valid) do
    decision = Gate.evaluate(valid, stream.context, stream.opts)

    if Decision.allowed?(decision) do
      {emittable, pending} = split_emittable(combined, decision.hits, stream, valid)

      emitted =
        sanitize_allowed(emittable, decision.hits, byte_size(emittable), decision, stream.opts)

      {%{stream | pending: pending, decision: decision}, decision, emitted}
    else
      {%{stream | pending: "", halted?: true, decision: decision}, decision, ""}
    end
  end

  defp halt(stream, reason) do
    decision = %Decision{
      verdict: :blocked,
      action: :block,
      phase: stream.context.phase,
      risk_level: :high,
      trust_level: stream.context.trust_level,
      reason: reason
    }

    {%{stream | pending: "", halted?: true, decision: decision}, decision, ""}
  end

  @doc """
  Flush the held-back content at end of stream.

  Returns `{stream, decision, emitted_chunk}`. If the final decision blocks
  or requires confirmation, no content is emitted.
  """
  @spec finish(t()) :: {t(), Decision.t(), String.t()}
  def finish(%__MODULE__{halted?: true, decision: %Decision{} = decision} = stream) do
    {stream, decision, ""}
  end

  def finish(%__MODULE__{} = stream) do
    if String.valid?(stream.pending),
      do: finish_valid(stream),
      else: halt(stream, "incomplete UTF-8")
  end

  defp finish_valid(stream) do
    decision = Gate.evaluate(stream.pending, stream.context, stream.opts)
    emitted = if Decision.allowed?(decision), do: decision.sanitized_text || "", else: ""

    {%{stream | pending: "", decision: decision}, decision, emitted}
  end

  defp split_emittable(text, hits, stream, valid) do
    base_size = max(byte_size(valid) - stream.window_bytes, 0)
    candidate_start = candidate_start(valid, stream.opts)

    emit_size =
      base_size
      |> min(candidate_start)
      |> safe_emit_size(hits)
      |> utf8_boundary(valid)

    {
      binary_part(text, 0, emit_size),
      binary_part(text, emit_size, byte_size(text) - emit_size)
    }
  end

  defp candidate_start(text, opts) do
    patterns = Keyword.get(opts, :patterns, Patterns.built_in())
    built_in? = patterns == Patterns.built_in()

    literal? =
      is_list(patterns) and
        Enum.all?(patterns, &Regex.match?(~r/\A[a-zA-Z0-9 _-]+\z/, Regex.source(&1.regex)))

    if (built_in? or literal?) and not Keyword.has_key?(opts, :indicator_sets) and
         Keyword.get(opts, :pipeline, :staged) in [:staged, :regex] do
      case Regex.run(@unbounded_prefix, text, return: :index) do
        [{offset, _}] -> offset
        nil -> byte_size(text)
      end
    else
      0
    end
  end

  defp utf8_boundary(0, _), do: 0

  defp utf8_boundary(size, text) do
    if Bitwise.band(:binary.at(text, size), 0xC0) == 0x80,
      do: utf8_boundary(size - 1, text),
      else: size
  end

  defp safe_emit_size(base_size, hits) do
    hits
    |> Enum.sort_by(& &1.offset, :desc)
    |> Enum.reduce(base_size, fn hit, emit_size ->
      if crosses_boundary?(hit, emit_size), do: min(emit_size, hit.offset), else: emit_size
    end)
  end

  defp crosses_boundary?(hit, emit_size) do
    hit.offset < emit_size and hit.offset + hit.length > emit_size
  end

  defp sanitize_allowed(emittable, hits, emit_size, %Decision{action: :redact}, opts) do
    emittable_hits = Enum.filter(hits, &contained?(&1, emit_size))
    Scanner.redact(emittable, emittable_hits, opts)
  end

  defp sanitize_allowed(emittable, _, _, _, _), do: emittable

  defp contained?(hit, emit_size), do: hit.offset + hit.length <= emit_size

  # Width hints set a minimum; candidate_start/2 handles expressions for which
  # a finite holdback cannot prove a safe emission boundary.
  defp stream_window_bytes(opts) do
    max(configured_window(opts), active_max_match_bytes(opts))
  end

  defp configured_window(opts) do
    case Keyword.get(opts, :stream_window_bytes, @default_window_bytes) do
      value when is_integer(value) and value > 0 -> value
      _ -> @default_window_bytes
    end
  end

  defp validate_options!(opts) do
    unless is_list(opts) and Keyword.keyword?(opts),
      do: raise(ArgumentError, "stream options must be a keyword list")

    patterns = Keyword.get(opts, :patterns, Patterns.built_in())

    unless valid_patterns?(patterns),
      do:
        raise(
          ArgumentError,
          "stream patterns must contain compiled regexes and positive integer widths"
        )
  end

  defp valid_patterns?([]), do: true

  defp valid_patterns?([%{regex: %Regex{}} = pattern | rest]) do
    width = Map.get(pattern, :max_match_bytes, Patterns.default_max_match_bytes())
    is_integer(width) and width > 0 and valid_patterns?(rest)
  end

  defp valid_patterns?(_), do: false

  defp active_max_match_bytes(opts) do
    patterns = Keyword.get(opts, :patterns, Patterns.built_in())

    Enum.reduce(patterns, Patterns.largest_max_match_bytes(patterns), fn pattern, width ->
      max(width, byte_size(Regex.source(pattern.regex)))
    end)
  end
end
