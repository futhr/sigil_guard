defmodule SigilGuard.StreamingVectorFixture do
  @moduledoc false

  alias SigilGuard.Canonical.JCS
  alias SigilGuard.Context
  alias SigilGuard.Runtime.Gate
  alias SigilGuard.Runtime.Stream

  @root SigilGuard.FixturePath.path("streaming")
  @context [phase: :tool_result, sink: :model, trust_level: :medium]

  # Each text embeds one built-in secret with boundary-clean surrounding bytes.
  @pattern_texts [
    {"aws_access_key", "aws key AKIAIOSFODNN7EXAMPLE stored"},
    {"generic_api_key", "config api_key=R7v9K2mQ4xZ8pL6nT5y0 ok"},
    {"bearer_token", "auth Bearer R7v9K2mQ4xZ8pL6nT5y0wxyz done"},
    {"database_uri", "db postgres://user:p4ssw0rd@dbhost stuff"},
    {"private_key", "-----BEGIN RSA PRIVATE KEY----- more"},
    {"generic_secret", "cfg secret=R7v9K2mQ4xZ8pL6n done"}
  ]

  @combining <<0xCC, 0x81>>
  @cyrillic_a <<0xD0, 0x90>>

  @doc false
  @spec path() :: Path.t()
  def path, do: Path.join(@root, "split_secret_vectors.json")

  @doc false
  @spec write!() :: :ok
  def write! do
    File.mkdir_p!(@root)
    File.write!(path(), json())
  end

  @doc false
  @spec json() :: binary()
  def json do
    {:ok, encoded} = JCS.encode(%{"vectors" => vectors()})
    encoded
  end

  @doc false
  @spec context() :: keyword()
  def context, do: @context

  @doc false
  @spec vectors() :: [map()]
  def vectors do
    per_pattern_vectors() ++ special_vectors() ++ confusable_vectors()
  end

  # -- Per-pattern split vectors ----------------------------------------------

  defp per_pattern_vectors do
    Enum.flat_map(@pattern_texts, fn {name, text} ->
      {offset, length} = span(text, name)

      [
        vector("#{name}.first_byte", split_at(text, 1)),
        vector("#{name}.before_match_end", split_at(text, offset + length - 1)),
        vector("#{name}.mid_match", split_at(text, offset + div(length, 2)))
      ]
    end)
  end

  # -- Special split vectors --------------------------------------------------

  defp special_vectors do
    mid_codepoint = "café AKIAIOSFODNN7EXAMPLE end"
    grapheme = "grapheme e" <> @combining <> " AKIAIOSFODNN7EXAMPLE end"
    all_one_byte = "onebyte AKIAIOSFODNN7EXAMPLE tail"

    [
      # Split inside the two-byte "é" codepoint.
      vector("mid_codepoint", split_at(mid_codepoint, 4)),
      # Split inside the "e" + U+0301 grapheme cluster.
      vector("grapheme_cluster", split_at(grapheme, byte_size("grapheme e"))),
      vector("all_one_byte", one_byte_chunks(all_one_byte))
    ]
  end

  # -- Unicode-confusable negatives (MUST NOT match or redact) -----------------

  defp confusable_vectors do
    cyrillic = "fake " <> @cyrillic_a <> "KIAIOSFODNN7EXAMPLE end"
    too_short = "near AKIAIOSFODNN7EXAMP end"

    [
      vector("confusable.cyrillic_a", split_at(cyrillic, 6)),
      vector("confusable.too_short_key", split_at(too_short, 7))
    ]
  end

  # -- Vector construction (golden values from the implementation) ------------

  defp vector(name, chunks) do
    text = IO.iodata_to_binary(chunks)

    %{
      "name" => name,
      "chunks" => Enum.map(chunks, &Base.encode64/1),
      "patterns" => "built_in",
      "expected_hit_names" => hit_names(text),
      "expected_emitted" => stream_output(chunks)
    }
  end

  @doc false
  @spec stream_output([binary()]) :: binary()
  def stream_output(chunks) do
    {stream, pieces} =
      Enum.reduce(chunks, {Stream.new(@context, []), []}, fn chunk, {stream, acc} ->
        {stream, _, piece} = Stream.push(stream, chunk)
        {stream, [piece | acc]}
      end)

    {_, _, final} = Stream.finish(stream)
    IO.iodata_to_binary([Enum.reverse(pieces), final])
  end

  @doc false
  @spec hit_names(binary()) :: [String.t()]
  def hit_names(text) do
    text
    |> Gate.evaluate(Context.new(@context), [])
    |> Map.get(:hits, [])
    |> Enum.map(& &1.name)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp span(text, name) do
    {:hit, hits} = SigilGuard.Scanner.scan(text)
    hit = Enum.find(hits, &(&1.name == name))
    {hit.offset, hit.length}
  end

  defp split_at(text, pos) do
    [binary_part(text, 0, pos), binary_part(text, pos, byte_size(text) - pos)]
  end

  defp one_byte_chunks(text), do: for(<<byte <- text>>, do: <<byte>>)
end
