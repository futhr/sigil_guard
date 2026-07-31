defmodule SigilGuard.RuntimeDependencySetTest do
  @moduledoc false

  use ExUnit.Case, async: true

  @expected_runtime_dependencies MapSet.new([:jason, :nimble_options, :telemetry])
  @expected_otp_extra_applications MapSet.new([:crypto, :logger])

  test "runtime dependency closure contains only the approved minimal set" do
    assert runtime_dependency_closure(Mix.Project.config(), Mix.Dep.Lock.read()) ==
             @expected_runtime_dependencies
  end

  test "project declares only expected OTP extra applications" do
    assert SigilGuard.MixProject.application()
           |> Keyword.fetch!(:extra_applications)
           |> MapSet.new() == @expected_otp_extra_applications
  end

  test "dependency-set assertion reports unexpected and missing dependencies" do
    actual = MapSet.new([:finch, :jason, :telemetry])

    assert dependency_set_diff(actual, @expected_runtime_dependencies) == %{
             missing: [:nimble_options],
             unexpected: [:finch]
           }
  end

  defp runtime_dependency_closure(project, locks) do
    project
    |> runtime_root_dependencies()
    |> dependency_closure(locks)
  end

  defp runtime_root_dependencies(project) do
    project
    |> Keyword.fetch!(:deps)
    |> Enum.flat_map(fn
      {name, requirement} when is_binary(requirement) ->
        [name]

      {name, opts} when is_list(opts) ->
        if runtime_dependency?(opts), do: [name], else: []

      {name, requirement, opts} when is_binary(requirement) and is_list(opts) ->
        if runtime_dependency?(opts), do: [name], else: []

      {_, _, opts} when is_list(opts) ->
        []
    end)
    |> MapSet.new()
  end

  defp runtime_dependency?(opts) do
    Keyword.get(opts, :runtime, true) != false and
      production_dependency?(Keyword.get(opts, :only, :all))
  end

  defp production_dependency?(:all), do: true
  defp production_dependency?(:prod), do: true
  defp production_dependency?(env) when is_atom(env), do: false
  defp production_dependency?(envs) when is_list(envs), do: :prod in envs
  defp production_dependency?(_), do: false

  defp dependency_closure(root_dependencies, locks) do
    root_dependencies
    |> Enum.reduce(root_dependencies, &include_lock_dependencies(&1, &2, locks))
  end

  defp include_lock_dependencies(name, seen, locks) do
    locks
    |> Map.fetch!(name)
    |> lock_dependency_names()
    |> Enum.reduce(seen, fn child, acc ->
      if MapSet.member?(acc, child) do
        acc
      else
        include_lock_dependencies(child, MapSet.put(acc, child), locks)
      end
    end)
  end

  defp lock_dependency_names({:hex, _, _, _, _, dependencies, _, _}) do
    dependencies
    |> Enum.reject(&optional_lock_dependency?/1)
    |> Enum.map(&lock_dependency_name/1)
  end

  defp lock_dependency_names(_), do: []

  defp optional_lock_dependency?({_, _, opts}), do: Keyword.get(opts, :optional, false)
  defp optional_lock_dependency?(_), do: true

  defp lock_dependency_name({name, _, opts}), do: Keyword.get(opts, :hex, name)

  defp dependency_set_diff(actual, expected) do
    %{
      missing: sorted_difference(expected, actual),
      unexpected: sorted_difference(actual, expected)
    }
  end

  defp sorted_difference(left, right) do
    left
    |> MapSet.difference(right)
    |> MapSet.to_list()
    |> Enum.sort()
  end
end
