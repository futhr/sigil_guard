defmodule SigilGuard.Canonical.JSON do
  @moduledoc false

  @doc false
  @spec decode(binary()) :: {:ok, term()} | {:error, :invalid_json}
  def decode(bytes) when is_binary(bytes) do
    case Jason.decode(bytes, objects: :ordered_objects) do
      {:ok, value} -> native_value(value)
      {:error, _} -> {:error, :invalid_json}
    end
  end

  def decode(_), do: {:error, :invalid_json}

  @doc false
  @spec unique_keys?(map()) :: boolean()
  def unique_keys?(map) do
    keys = Enum.map(Map.keys(map), &string_key/1)
    length(keys) == MapSet.size(MapSet.new(keys))
  end

  defp string_key(key) when is_atom(key), do: Atom.to_string(key)
  defp string_key(key), do: key

  defp native_value(%Jason.OrderedObject{values: pairs}) do
    Enum.reduce_while(pairs, {:ok, %{}}, fn {key, value}, {:ok, map} ->
      case native_entry(map, key, value) do
        {:ok, map} -> {:cont, {:ok, map}}
        error -> {:halt, error}
      end
    end)
  end

  defp native_value(values) when is_list(values), do: native_list(values, [])
  defp native_value(value), do: {:ok, value}

  defp native_entry(map, key, value) do
    with false <- Map.has_key?(map, key),
         {:ok, native} <- native_value(value) do
      {:ok, Map.put(map, key, native)}
    else
      _ -> {:error, :invalid_json}
    end
  end

  defp native_list([], acc), do: {:ok, Enum.reverse(acc)}

  defp native_list([value | rest], acc) do
    with {:ok, native} <- native_value(value), do: native_list(rest, [native | acc])
  end
end
