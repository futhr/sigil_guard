defmodule SigilGuard.FixturePath do
  @moduledoc """
  Resolves test fixture paths from the repository-owned `test/fixtures` root.

  Tests use this helper instead of cwd-relative strings so focused runs work
  the same from the repository root, subdirectories, and Mix task contexts.
  """

  @root Path.expand("../fixtures", __DIR__)

  @doc """
  Return the absolute path to a fixture file or directory.
  """
  @spec path(Path.t() | [Path.t()]) :: Path.t()
  def path(parts) when is_list(parts), do: Path.join([@root | parts])
  def path(path) when is_binary(path), do: Path.join(@root, path)

  @doc """
  Read fixture bytes.
  """
  @spec read!(Path.t() | [Path.t()]) :: binary()
  def read!(parts), do: File.read!(path(parts))

  @doc """
  Read and decode a JSON fixture.
  """
  @spec read_json!(Path.t() | [Path.t()]) :: map() | list()
  def read_json!(parts) do
    parts
    |> read!()
    |> Jason.decode!()
  end
end
