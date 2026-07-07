defmodule Mix.Tasks.Sigil.LivebookCheck do
  @shortdoc "Validate Livebook Elixir cells offline"

  @moduledoc """
  Executes Elixir code cells from repository Livebooks in child `elixir`
  processes with Hex and Rebar offline mode enabled.

      mix sigil.livebook_check
      mix sigil.livebook_check notebooks/quick-start.livemd

  With no arguments, all `notebooks/*.livemd` files are validated.
  """

  use Mix.Task

  @type check_result :: :ok | {:error, [String.t()]}
  @type check_opts :: [root: Path.t(), env: [{String.t(), String.t()}]]

  @impl Mix.Task
  @doc """
  Run Livebook validation and raise when any notebook fails.
  """
  @spec run([String.t()]) :: :ok
  def run(args) do
    case check(args, root: File.cwd!()) do
      :ok ->
        Mix.shell().info("Livebook check passed")

      {:error, failures} ->
        failures
        |> Enum.join("\n\n")
        |> Mix.raise()
    end
  end

  @doc """
  Validate the selected Livebooks.

  Passing an empty path list validates every `notebooks/*.livemd` file under
  `:root`. Each notebook is converted into a temporary `.exs` file beside the
  notebook so `__DIR__` keeps the same value as it has in Livebook.
  """
  @spec check([String.t()], check_opts()) :: check_result()
  def check(paths \\ [], opts \\ []) when is_list(paths) and is_list(opts) do
    root = opts |> Keyword.get(:root, File.cwd!()) |> Path.expand()
    env = Keyword.get(opts, :env, offline_env())

    root
    |> selected_notebooks(paths)
    |> Enum.map(&run_notebook(&1, root, env))
    |> Enum.flat_map(fn
      :ok -> []
      {:error, failure} -> [failure]
    end)
    |> case do
      [] -> :ok
      failures -> {:error, failures}
    end
  end

  @doc """
  Extract Elixir fenced-code cells from Livebook markdown.
  """
  @spec elixir_cells(String.t()) :: [String.t()]
  def elixir_cells(markdown) when is_binary(markdown) do
    ~r/```elixir\s*\n(.*?)\n```/s
    |> Regex.scan(markdown, capture: :all_but_first)
    |> Enum.map(fn [cell] -> cell end)
  end

  defp selected_notebooks(root, []) do
    root
    |> Path.join("notebooks/*.livemd")
    |> Path.wildcard()
    |> Enum.sort()
  end

  defp selected_notebooks(root, paths) do
    Enum.map(paths, fn path ->
      path
      |> Path.expand(root)
      |> require_livebook!()
    end)
  end

  defp require_livebook!(path) do
    if File.regular?(path) do
      path
    else
      Mix.raise("Livebook not found: #{path}")
    end
  end

  defp run_notebook(path, root, env) do
    script = script_for(path)
    script_path = temp_script_path(path)

    try do
      File.write!(script_path, script)

      case System.cmd("elixir", [script_path], cd: root, env: env, stderr_to_stdout: true) do
        {_output, 0} ->
          :ok

        {output, status} ->
          failed_notebook(path, root, status, output)
      end
    after
      File.rm(script_path)
    end
  end

  defp script_for(path) do
    path
    |> File.read!()
    |> elixir_cells()
    |> Enum.with_index(1)
    |> Enum.map_join("\n\n", fn {cell, index} ->
      "# -- #{Path.basename(path)} cell #{index} --\n" <> cell
    end)
  end

  defp temp_script_path(path) do
    suffix = System.unique_integer([:positive])
    Path.join(Path.dirname(path), ".sigil_livebook_check_#{suffix}.exs")
  end

  defp failed_notebook(path, root, status, output) do
    relative = Path.relative_to(path, root)
    trimmed = String.trim(output)

    {:error,
     [
       "#{relative} failed with exit #{status}",
       if(trimmed == "", do: "(no output)", else: trimmed)
     ]
     |> Enum.join("\n")}
  end

  defp offline_env do
    [
      {"HEX_OFFLINE", "1"},
      {"REBAR_OFFLINE", "1"}
    ]
  end
end
