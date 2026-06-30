defmodule SigilGuard.Runtime.Stream do
  @moduledoc """
  Chunk-safe sanitizer for streaming runtime output.

  Streaming output can split credentials or prompt-injection phrases across
  chunk boundaries. This module keeps a configurable trailing holdback window,
  evaluates each buffered boundary crossing with `SigilGuard.Runtime.Gate`,
  and only emits content that is outside the holdback window.

  If the gate blocks or requires confirmation, no new content is emitted and
  the stream is marked halted. Callers can inspect the returned decision to
  decide whether to drop, quarantine, or request approval.
  """

  alias SigilGuard.Context
  alias SigilGuard.Decision
  alias SigilGuard.Runtime.Gate
  alias SigilGuard.Scanner

  @default_window_bytes 256

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
  to `#{@default_window_bytes}` bytes.
  """
  @spec new(Context.t() | map() | keyword(), keyword()) :: t()
  def new(context \\ %Context{}, opts \\ []) do
    %__MODULE__{
      context: Context.new(context),
      opts: opts,
      window_bytes: Keyword.get(opts, :stream_window_bytes, @default_window_bytes)
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
    decision = Gate.evaluate(combined, stream.context, stream.opts)

    if Decision.allowed?(decision) do
      hits = scan_hits(combined, stream.opts)
      {emittable, pending} = split_emittable(combined, hits, stream.window_bytes)
      emitted = sanitize_allowed(emittable, hits, byte_size(emittable), decision, stream.opts)

      {%{stream | pending: pending, decision: decision}, decision, emitted}
    else
      {%{stream | pending: combined, halted?: true, decision: decision}, decision, ""}
    end
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
    decision = Gate.evaluate(stream.pending, stream.context, stream.opts)
    emitted = if Decision.allowed?(decision), do: decision.sanitized_text || "", else: ""

    {%{stream | pending: "", decision: decision}, decision, emitted}
  end

  defp scan_hits("", _), do: []

  defp scan_hits(text, opts) do
    case Scanner.scan(text, opts) do
      {:ok, _} -> []
      {:hit, hits} -> hits
    end
  end

  defp split_emittable(text, hits, window_bytes) do
    base_size = max(byte_size(text) - window_bytes, 0)
    emit_size = safe_emit_size(base_size, hits)

    {
      binary_part(text, 0, emit_size),
      binary_part(text, emit_size, byte_size(text) - emit_size)
    }
  end

  defp safe_emit_size(base_size, hits) do
    Enum.reduce(hits, base_size, fn hit, emit_size ->
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
end
