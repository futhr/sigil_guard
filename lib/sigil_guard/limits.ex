defmodule SigilGuard.Limits do
  @moduledoc """
  Bounded work validation for untrusted JSON-shaped input.

  Defaults allow 1 MiB of binary data, 100,000 nodes and 64 nested containers.
  Hosts still own transport, request concurrency and timeout limits.
  """

  @doc "Check byte, node and nesting budgets before normalization or cryptography."
  @spec check(term(), keyword()) :: :ok | {:error, :invalid_payload}
  def check(value, opts \\ []) do
    bytes = Keyword.get(opts, :max_input_bytes, 1_048_576)
    nodes = Keyword.get(opts, :max_input_nodes, 100_000)
    depth = Keyword.get(opts, :max_input_depth, 64)

    if Enum.all?([bytes, nodes, depth], &(is_integer(&1) and &1 > 0)) do
      case visit(value, bytes, nodes, depth) do
        {:ok, _, _} -> :ok
        :error -> {:error, :invalid_payload}
      end
    else
      {:error, :invalid_payload}
    end
  end

  defp visit(_, bytes, nodes, depth) when bytes < 0 or nodes <= 0 or depth < 0, do: :error

  defp visit(value, bytes, nodes, _) when is_binary(value) do
    if byte_size(value) <= bytes, do: {:ok, bytes - byte_size(value), nodes - 1}, else: :error
  end

  defp visit(%_{}, _, _, _), do: :error

  defp visit(value, bytes, nodes, depth) when is_map(value) do
    Enum.reduce_while(value, {:ok, bytes, nodes - 1}, fn {key, child}, {:ok, bytes, nodes} ->
      with {:ok, bytes, nodes} <- visit(key, bytes, nodes, depth - 1),
           {:ok, bytes, nodes} <- visit(child, bytes, nodes, depth - 1) do
        {:cont, {:ok, bytes, nodes}}
      else
        :error -> {:halt, :error}
      end
    end)
  end

  defp visit(value, bytes, nodes, depth) when is_list(value),
    do: visit_list(value, bytes, nodes - 1, depth - 1)

  defp visit(value, bytes, nodes, _) when is_atom(value) or is_number(value),
    do: {:ok, bytes, nodes - 1}

  defp visit(_, _, _, _), do: :error

  defp visit_list([], bytes, nodes, _) when bytes >= 0 and nodes >= 0, do: {:ok, bytes, nodes}

  defp visit_list([head | tail], bytes, nodes, depth) do
    with {:ok, bytes, nodes} <- visit(head, bytes, nodes, depth),
         do: visit_list(tail, bytes, nodes, depth)
  end

  defp visit_list(_, _, _, _), do: :error
end
