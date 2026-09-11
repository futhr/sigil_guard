defmodule SigilGuard.Canonical.LegacyJSON do
  @moduledoc false

  @doc false
  @spec encode(term()) :: binary() | [list() | ?[ | ?] | ?{ | ?}, ...]
  def encode(value) when is_map(value) do
    parts =
      value
      |> Enum.map(fn {key, item} -> {canonical_key(key), item} end)
      |> require_unique_keys!()
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.map(fn {key, item} -> [Jason.encode!(key), ?:, encode(item)] end)
      |> Enum.intersperse(",")

    [?{, parts, ?}]
  end

  def encode(value) when is_list(value) do
    value
    |> Enum.map(&encode/1)
    |> Enum.intersperse(",")
    |> then(&[?[, &1, ?]])
  end

  def encode(value)
      when is_atom(value) and not is_boolean(value) and not is_nil(value) do
    value
    |> Atom.to_string()
    |> Jason.encode!()
  end

  def encode(value) do
    Jason.encode!(value)
  end

  @doc false
  @spec valid?(term()) :: boolean()
  def valid?(%_{}), do: false

  def valid?(value) when is_map(value) do
    pairs = Enum.map(value, fn {key, item} -> {canonical_key(key), item} end)
    keys = Enum.map(pairs, &elem(&1, 0))

    length(keys) == MapSet.size(MapSet.new(keys)) and
      Enum.all?(pairs, fn {key, item} -> String.valid?(key) and valid?(item) end)
  rescue
    _ in [ArgumentError, Protocol.UndefinedError] -> false
  end

  def valid?([]), do: true
  def valid?([value | rest]), do: valid?(value) and valid?(rest) and is_list(rest)
  def valid?(value) when is_binary(value), do: String.valid?(value)
  def valid?(value), do: is_atom(value) or is_number(value)

  defp canonical_key(key) when is_atom(key), do: Atom.to_string(key)
  defp canonical_key(key) when is_binary(key), do: key

  defp canonical_key(key) do
    to_string(key)
  rescue
    UnicodeConversionError ->
      reraise ArgumentError, "invalid Unicode in JSON object key", __STACKTRACE__
  end

  defp require_unique_keys!(pairs) do
    keys = Enum.map(pairs, &elem(&1, 0))

    if length(keys) != MapSet.size(MapSet.new(keys)) do
      raise ArgumentError, "duplicate JSON object key after normalization"
    end

    pairs
  end
end
