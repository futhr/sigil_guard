defmodule SigilGuard.Canonical.JCSTest do
  @moduledoc false

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias SigilGuard.Canonical.JCS

  @fixture_path SigilGuard.FixturePath.path("jcs/adversarial_corpus.json")

  test "integer-position finite floats do not acquire a trailing decimal point" do
    assert JCS.encode(float_from_hex("435ce41d9a334d1d")) == {:ok, "32528460560544884"}
    assert JCS.encode(float_from_hex("c35ce41d9a334d1d")) == {:ok, "-32528460560544884"}
  end

  test "improper lists return an error at any nesting level" do
    assert JCS.encode([1 | 2]) == {:error, :invalid_map}
    assert JCS.encode(%{"nested" => [1 | 2]}) == {:error, :invalid_map}
  end

  describe "encode/1" do
    test "matches the RFC 8785 canonical JSON sample byte-for-byte" do
      value = %{
        "numbers" => [333_333_333.33333329, 1.0e30, 4.50, 2.0e-3, 1.0e-27],
        "string" => "€$\u000F\nA'B\"\\\\\"/",
        "literals" => [nil, true, false]
      }

      assert JCS.encode(value) ==
               {:ok,
                "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"€$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"}
    end

    test "matches RFC 8785 Appendix B number serialization samples" do
      samples = [
        {"0000000000000000", "0"},
        {"8000000000000000", "0"},
        {"0000000000000001", "5e-324"},
        {"8000000000000001", "-5e-324"},
        {"7fefffffffffffff", "1.7976931348623157e+308"},
        {"ffefffffffffffff", "-1.7976931348623157e+308"},
        {"44b52d02c7e14af5", "9.999999999999997e+22"},
        {"44b52d02c7e14af6", "1e+23"},
        {"44b52d02c7e14af7", "1.0000000000000001e+23"},
        {"444b1ae4d6e2ef4e", "999999999999999700000"},
        {"444b1ae4d6e2ef4f", "999999999999999900000"},
        {"444b1ae4d6e2ef50", "1e+21"},
        {"3eb0c6f7a0b5ed8c", "9.999999999999997e-7"},
        {"3eb0c6f7a0b5ed8d", "0.000001"},
        {"41b3de4355555553", "333333333.3333332"},
        {"41b3de4355555554", "333333333.33333325"},
        {"41b3de4355555555", "333333333.3333333"},
        {"41b3de4355555556", "333333333.3333334"},
        {"41b3de4355555557", "333333333.33333343"},
        {"becbf647612f3696", "-0.0000033333333333333333"},
        {"43143ff3c1cb0959", "1424953923781206.2"}
      ]

      for {ieee754_hex, expected} <- samples do
        assert JCS.encode(float_from_hex(ieee754_hex)) == {:ok, expected}
      end
    end

    test "sorts object keys by UTF-16 code units" do
      value = %{
        "€" => "Euro Sign",
        "\r" => "Carriage Return",
        "דּ" => "Hebrew Letter Dalet With Dagesh",
        "1" => "One",
        "😀" => "Emoji: Grinning Face",
        "\u0080" => "Control",
        "ö" => "Latin Small Letter O With Diaeresis"
      }

      assert JCS.encode(value) ==
               {:ok,
                "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"דּ\":\"Hebrew Letter Dalet With Dagesh\"}"}
    end

    test "does not normalize unicode keys or string values" do
      value = %{
        "e\u0301" => "e\u0301",
        "é" => "é"
      }

      assert JCS.encode(value) == {:ok, "{\"é\":\"é\",\"é\":\"é\"}"}
    end

    test "normalizes atom keys and atom values" do
      assert JCS.encode(%{phase: :tool_request, allowed: true, skipped: nil}) ==
               {:ok, "{\"allowed\":true,\"phase\":\"tool_request\",\"skipped\":null}"}
    end

    test "rejects integers outside the I-JSON safe integer range" do
      assert JCS.encode(9_007_199_254_740_991) == {:ok, "9007199254740991"}
      assert JCS.encode(-9_007_199_254_740_991) == {:ok, "-9007199254740991"}
      assert JCS.encode(9_007_199_254_740_992) == {:error, :unsupported_number_range}
      assert JCS.encode(-9_007_199_254_740_992) == {:error, :unsupported_number_range}
    end

    test "rejects non-json-representable terms" do
      assert JCS.encode({:tuple}) == {:error, :invalid_map}
      assert JCS.encode(self()) == {:error, :invalid_map}
      assert JCS.encode(%URI{path: "/"}) == {:error, :invalid_map}
      assert JCS.encode(%{"ok" => fn -> :ok end}) == {:error, :invalid_map}
    end

    test "rejects invalid UTF-8 strings and keys" do
      invalid = <<0xFF>>

      assert JCS.encode(invalid) == {:error, :invalid_map}
      assert JCS.encode(%{invalid => "value"}) == {:error, :invalid_map}
    end

    test "rejects non-string map keys after normalization" do
      assert JCS.encode(%{1 => "integer key"}) == {:error, :invalid_map}
      assert JCS.encode(%{{:tuple, :key} => "tuple key"}) == {:error, :invalid_map}
    end

    test "normalizes decimal float formatting branches" do
      assert JCS.encode(1.5) == {:ok, "1.5"}
      assert JCS.encode(-0.0) == {:ok, "0"}
      assert JCS.encode(1.0e20) == {:ok, "100000000000000000000"}
      assert JCS.encode(1.0e-6) == {:ok, "0.000001"}
      assert JCS.encode(1.0e-7) == {:ok, "1e-7"}
    end

    test "rejects key collisions after atom-to-string normalization" do
      assert JCS.encode(%{:phase => "atom", "phase" => "string"}) == {:error, :invalid_map}
    end
  end

  describe "adversarial corpus" do
    for case <- File.read!(@fixture_path) |> Jason.decode!() do
      @case case

      test @case["name"] do
        assert_corpus_case(@case)
      end
    end
  end

  describe "properties" do
    property "equal maps yield identical canonical bytes regardless of construction order" do
      check all(pairs <- json_pairs(), max_runs: 100) do
        forward = Map.new(pairs)

        reverse =
          pairs
          |> Enum.reverse()
          |> Map.new()

        assert JCS.encode(forward) == JCS.encode(reverse)
      end
    end

    property "encoding is stable through decode and re-encode for JSON terms" do
      check all(value <- json_term(), max_runs: 100) do
        assert {:ok, canonical} = JCS.encode(value)
        assert {:ok, decoded} = Jason.decode(canonical)
        assert JCS.encode(decoded) == {:ok, canonical}
      end
    end

    property "map keys are emitted in UTF-16 code-unit order" do
      check all(pairs <- adversarial_pairs(), max_runs: 100) do
        assert {:ok, canonical} = JCS.encode(Map.new(pairs))
        expected = expected_ordered_object(pairs)

        assert canonical == expected
      end
    end
  end

  defp float_from_hex(hex) do
    <<bits::64>> = Base.decode16!(String.upcase(hex))
    <<float::float-64>> = <<bits::64>>
    float
  end

  defp assert_corpus_case(%{"kind" => "term", "input" => input, "expected" => expected}) do
    assert JCS.encode(input) == {:ok, expected}
  end

  defp assert_corpus_case(%{"kind" => "float_hex", "hex" => hex, "expected" => expected}) do
    assert JCS.encode(float_from_hex(hex)) == {:ok, expected}
  end

  defp assert_corpus_case(%{
         "kind" => "error",
         "input" => input,
         "expected_error" => expected_error
       }) do
    assert JCS.encode(input) == {:error, String.to_existing_atom(expected_error)}
  end

  defp assert_corpus_case(%{
         "kind" => "invalid_utf8_hex",
         "hex" => hex,
         "expected_error" => expected_error
       }) do
    invalid = Base.decode16!(String.upcase(hex))

    assert JCS.encode(invalid) == {:error, String.to_existing_atom(expected_error)}
  end

  defp assert_corpus_case(%{
         "kind" => "atom_string_collision",
         "expected_error" => expected_error
       }) do
    assert JCS.encode(%{:phase => "atom", "phase" => "string"}) ==
             {:error, String.to_existing_atom(expected_error)}
  end

  defp json_term do
    StreamData.sized(&json_term/1)
  end

  defp json_term(0) do
    StreamData.one_of([
      StreamData.constant(nil),
      StreamData.boolean(),
      safe_integer(),
      json_string()
    ])
  end

  defp json_term(size) do
    child_size = div(size, 2)

    StreamData.one_of([
      json_term(0),
      StreamData.list_of(json_term(child_size), max_length: 4),
      json_map(child_size)
    ])
  end

  defp json_map(size) do
    StreamData.map(json_pairs(size), &Map.new/1)
  end

  defp json_pairs(size \\ 3) do
    json_key()
    |> StreamData.map_of(json_term(size), max_length: 4)
    |> StreamData.map(&Map.to_list/1)
  end

  defp adversarial_pairs do
    adversarial_key()
    |> StreamData.map_of(safe_integer(), min_length: 1, max_length: 4)
    |> StreamData.map(&Map.to_list/1)
  end

  defp safe_integer do
    StreamData.integer(-9_007_199_254_740_991..9_007_199_254_740_991)
  end

  defp json_key do
    StreamData.member_of([
      "",
      "a",
      "aa",
      "ab",
      "1",
      "\r",
      "\u0080",
      "é",
      "e\u0301",
      "😀",
      "😁",
      "ﬀ",
      "דּ",
      "€"
    ])
  end

  defp json_string do
    StreamData.member_of([
      "",
      "plain",
      "quote\"backslash\\",
      "controls\b\t\n\f\r",
      "é",
      "e\u0301",
      "😀",
      "ﬀ",
      "€"
    ])
  end

  defp adversarial_key do
    json_key()
  end

  defp expected_ordered_object(pairs) do
    encoded_pairs =
      pairs
      |> Enum.sort_by(fn {key, _} -> utf16_sort_key(key) end)
      |> Enum.map(fn {key, value} ->
        {:ok, encoded_key} = JCS.encode(key)
        encoded_key <> ":" <> Integer.to_string(value)
      end)

    "{" <> Enum.join(encoded_pairs, ",") <> "}"
  end

  defp utf16_sort_key(key) do
    :unicode.characters_to_binary(key, :utf8, {:utf16, :big})
  end
end
