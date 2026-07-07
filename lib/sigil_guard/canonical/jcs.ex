defmodule SigilGuard.Canonical.JCS do
  @moduledoc """
  RFC 8785 JSON Canonicalization Scheme encoder.

  The encoder emits compact UTF-8 JSON with object keys sorted by UTF-16 code
  units, minimal string escaping, and ECMAScript-compatible number rendering.
  Integers are limited to the I-JSON safe integer range. Larger numeric values
  must be carried as JSON strings by callers.
  """

  import Bitwise

  @max_safe_integer 9_007_199_254_740_991
  @min_safe_integer -@max_safe_integer
  @nonfinite_exponent 0x7FF

  @type error_reason :: :unsupported_number_range | :invalid_map

  @doc """
  Encode a JSON-representable term as RFC 8785 canonical JSON bytes.

  Atom keys and non-literal atom values are normalized with `Atom.to_string/1`
  to match the SigilGuard 1.0 digest preimage rules. Any key collision after
  that normalization returns `{:error, :invalid_map}`.
  """
  @spec encode(term()) :: {:ok, binary()} | {:error, error_reason()}
  def encode(value) do
    with {:ok, iodata} <- encode_value(value) do
      {:ok, IO.iodata_to_binary(iodata)}
    end
  end

  defp encode_value(nil), do: {:ok, "null"}
  defp encode_value(true), do: {:ok, "true"}
  defp encode_value(false), do: {:ok, "false"}

  defp encode_value(value) when is_atom(value) do
    value
    |> Atom.to_string()
    |> encode_value()
  end

  defp encode_value(value) when is_binary(value) do
    if String.valid?(value) do
      {:ok, encode_string(value)}
    else
      {:error, :invalid_map}
    end
  end

  defp encode_value(value) when is_integer(value) do
    if value in @min_safe_integer..@max_safe_integer do
      {:ok, Integer.to_string(value)}
    else
      {:error, :unsupported_number_range}
    end
  end

  defp encode_value(value) when is_float(value) do
    if finite_float?(value) do
      {:ok, encode_float(value)}
    else
      {:error, :unsupported_number_range}
    end
  end

  defp encode_value(value) when is_list(value) do
    encode_list(value, [])
  end

  defp encode_value(%_{}), do: {:error, :invalid_map}

  defp encode_value(value) when is_map(value) do
    with {:ok, pairs} <- normalize_pairs(value),
         {:ok, encoded_pairs} <- encode_pairs(pairs, []) do
      {:ok, [?{, Enum.intersperse(encoded_pairs, ?,), ?}]}
    end
  end

  defp encode_value(_), do: {:error, :invalid_map}

  defp encode_list([], encoded) do
    {:ok, [?[, Enum.intersperse(Enum.reverse(encoded), ?,), ?]]}
  end

  defp encode_list([value | rest], encoded) do
    with {:ok, item} <- encode_value(value) do
      encode_list(rest, [item | encoded])
    end
  end

  defp normalize_pairs(map) do
    normalized =
      Enum.reduce_while(map, {:ok, []}, fn {key, value}, {:ok, pairs} ->
        case normalize_key(key) do
          {:ok, normalized_key} -> {:cont, {:ok, [{normalized_key, value} | pairs]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)

    case normalized do
      {:ok, pairs} ->
        if duplicate_normalized_keys?(pairs) do
          {:error, :invalid_map}
        else
          {:ok, Enum.sort_by(pairs, fn {key, _} -> utf16_sort_key(key) end)}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp normalize_key(key) when is_atom(key), do: {:ok, Atom.to_string(key)}

  defp normalize_key(key) when is_binary(key) do
    if String.valid?(key) do
      {:ok, key}
    else
      {:error, :invalid_map}
    end
  end

  defp normalize_key(_), do: {:error, :invalid_map}

  defp duplicate_normalized_keys?(pairs) do
    pairs
    |> Enum.map(fn {key, _} -> key end)
    |> then(&(Enum.uniq(&1) != &1))
  end

  defp utf16_sort_key(key) do
    :unicode.characters_to_binary(key, :utf8, {:utf16, :big})
  end

  defp encode_pairs([], encoded), do: {:ok, Enum.reverse(encoded)}

  defp encode_pairs([{key, value} | rest], encoded) do
    with {:ok, encoded_value} <- encode_value(value) do
      encode_pairs(rest, [[encode_string(key), ?:, encoded_value] | encoded])
    end
  end

  defp encode_string(value) do
    encoded_codepoints =
      value
      |> String.to_charlist()
      |> Enum.map(&encode_codepoint/1)

    [?", encoded_codepoints, ?"]
  end

  defp encode_codepoint(?"), do: "\\\""
  defp encode_codepoint(?\\), do: "\\\\"
  defp encode_codepoint(?\b), do: "\\b"
  defp encode_codepoint(?\t), do: "\\t"
  defp encode_codepoint(?\n), do: "\\n"
  defp encode_codepoint(?\f), do: "\\f"
  defp encode_codepoint(?\r), do: "\\r"

  defp encode_codepoint(codepoint) when codepoint < 0x20 do
    hex =
      codepoint
      |> Integer.to_string(16)
      |> String.downcase()
      |> String.pad_leading(4, "0")

    "\\u" <> hex
  end

  defp encode_codepoint(codepoint), do: <<codepoint::utf8>>

  defp finite_float?(value) do
    <<bits::64>> = <<value::float-64>>
    exponent = bits >>> 52 &&& 0x7FF
    exponent != @nonfinite_exponent
  end

  defp encode_float(value) do
    if value == 0.0 do
      "0"
    else
      value
      |> :erlang.float_to_binary([:short])
      |> ecmascript_float_string()
    end
  end

  defp ecmascript_float_string("-" <> raw), do: ["-", ecmascript_float_string(raw)]

  defp ecmascript_float_string(raw) do
    case String.split(raw, ["e", "E"], parts: 2) do
      [decimal] ->
        decimal
        |> trim_fraction_zeros()
        |> strip_negative_zero()

      [coefficient, exponent] ->
        coefficient
        |> decimal_components(String.to_integer(exponent))
        |> format_decimal_components()
    end
  end

  defp trim_fraction_zeros(decimal) do
    if String.contains?(decimal, ".") do
      decimal
      |> String.trim_trailing("0")
      |> String.trim_trailing(".")
    else
      decimal
    end
  end

  defp strip_negative_zero("-0"), do: "0"
  defp strip_negative_zero(value), do: value

  defp decimal_components(coefficient, exponent) do
    [integer, fraction] =
      case String.split(coefficient, ".", parts: 2) do
        [integer] -> [integer, ""]
        parts -> parts
      end

    trimmed_digits = String.trim_trailing(integer <> fraction, "0")
    digits = if trimmed_digits == "", do: "0", else: trimmed_digits

    decimal_exponent = String.length(integer) + exponent - 1
    {digits, decimal_exponent}
  end

  defp format_decimal_components({"0", _}), do: "0"

  defp format_decimal_components({digits, decimal_exponent}) do
    digit_count = String.length(digits)
    decimal_position = decimal_exponent + 1

    cond do
      decimal_position > 0 and decimal_position <= digit_count ->
        {integer, fraction} = String.split_at(digits, decimal_position)
        integer <> "." <> fraction

      digit_count < decimal_position and decimal_position <= 21 ->
        digits <> String.duplicate("0", decimal_position - digit_count)

      decimal_position > -6 and decimal_position <= 0 ->
        "0." <> String.duplicate("0", -decimal_position) <> digits

      true ->
        format_exponent(digits, decimal_exponent)
    end
  end

  defp format_exponent(<<first::binary-size(1)>>, decimal_exponent) do
    first <> "e" <> signed_exponent(decimal_exponent)
  end

  defp format_exponent(<<first::binary-size(1), rest::binary>>, decimal_exponent) do
    first <> "." <> rest <> "e" <> signed_exponent(decimal_exponent)
  end

  defp signed_exponent(exponent) when exponent >= 0, do: "+" <> Integer.to_string(exponent)
  defp signed_exponent(exponent), do: Integer.to_string(exponent)
end
