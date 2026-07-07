defmodule SigilGuard.Runtime.StreamingVectorsTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Runtime.Stream
  alias SigilGuard.StreamingVectorFixture

  @context [phase: :tool_result, sink: :model, trust_level: :medium]

  setup_all do
    {:ok, decoded} = Jason.decode(File.read!(StreamingVectorFixture.path()))
    %{vectors: decoded["vectors"]}
  end

  test "the committed vector file matches a fresh regeneration (golden)" do
    assert File.read!(StreamingVectorFixture.path()) == StreamingVectorFixture.json()
  end

  test "every vector streams to its exact expected_emitted and hit names", %{vectors: vectors} do
    assert length(vectors) >= 23

    for vector <- vectors do
      chunks = Enum.map(vector["chunks"], &Base.decode64!/1)
      text = IO.iodata_to_binary(chunks)

      assert run_stream(chunks) == vector["expected_emitted"], vector["name"]

      assert StreamingVectorFixture.hit_names(text) == vector["expected_hit_names"],
             vector["name"]
    end
  end

  test "the vector set covers each built-in pattern and every split class", %{vectors: vectors} do
    names = MapSet.new(vectors, & &1["name"])

    for pattern <- ~w(aws_access_key generic_api_key bearer_token database_uri private_key
                      generic_secret),
        split <- ~w(first_byte before_match_end mid_match) do
      assert MapSet.member?(names, "#{pattern}.#{split}"), "#{pattern}.#{split}"
    end

    for special <- ~w(mid_codepoint grapheme_cluster all_one_byte) do
      assert MapSet.member?(names, special), special
    end
  end

  test "Unicode-confusable vectors never match or redact", %{vectors: vectors} do
    confusables = Enum.filter(vectors, &String.starts_with?(&1["name"], "confusable."))
    assert length(confusables) >= 2

    for vector <- confusables do
      chunks = Enum.map(vector["chunks"], &Base.decode64!/1)
      text = IO.iodata_to_binary(chunks)

      assert vector["expected_hit_names"] == [], vector["name"]
      # The lookalike crosses verbatim - nothing is matched or redacted.
      assert vector["expected_emitted"] == text, vector["name"]
      assert run_stream(chunks) == text, vector["name"]
    end
  end

  defp run_stream(chunks) do
    {stream, pieces} =
      Enum.reduce(chunks, {Stream.new(@context, []), []}, fn chunk, {stream, acc} ->
        {stream, _, piece} = Stream.push(stream, chunk)
        {stream, [piece | acc]}
      end)

    {_, _, final} = Stream.finish(stream)
    IO.iodata_to_binary([Enum.reverse(pieces), final])
  end
end
