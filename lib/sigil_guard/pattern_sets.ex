defmodule SigilGuard.PatternSets do
  @moduledoc """
  Resolve bundle-supplied scanner pattern sets.

  The three pattern sets - `secret`, `injection`, `poisoning` - are distinct and
  each is independently overridable by a trust bundle. `resolve/1` compiles the
  trust-bundle `patterns` list into consumer-ready sets:
  the `secret` set feeds `SigilGuard.Scanner` (compiled pattern maps), while
  `injection` and `poisoning` feed `SigilGuard.Quarantine` (indicator maps). A
  set with at least one bundle entry replaces that set's built-in default
  entirely; a set absent from the bundle keeps its built-in default.

  Resolution is pure and never creates atoms from bundle input; entry `name`s
  stay strings (the scanner hit `name` / quarantine indicator `id`).
  """

  alias SigilGuard.Patterns
  alias SigilGuard.Quarantine

  @sets [:secret, :injection, :poisoning]
  @set_of %{
    "secret" => :secret,
    "injection" => :injection,
    "poisoning" => :poisoning,
    secret: :secret,
    injection: :injection,
    poisoning: :poisoning
  }
  @severity_of %{
    "low" => :low,
    "medium" => :medium,
    "high" => :high,
    low: :low,
    medium: :medium,
    high: :high
  }
  @default_severity :medium
  @max_match_bytes_limit 4096
  @default_max_match_bytes 256

  @typedoc "Resolved pattern sets: `secret` compiled patterns and `injection`/`poisoning` indicators."
  @type t :: %{
          secret: [Patterns.compiled_pattern()],
          injection: [map()],
          poisoning: [map()]
        }

  @doc "Return the three built-in pattern sets in consumer-ready shapes."
  @spec built_in() :: t()
  def built_in do
    %{
      secret: Patterns.built_in(),
      injection: Quarantine.built_in_indicators(:injection),
      poisoning: Quarantine.built_in_indicators(:poisoning)
    }
  end

  @doc """
  Resolve a trust bundle's `patterns` list into the three sets.

  Each supplied set replaces its built-in default; absent sets keep the default.
  A malformed entry (bad `set`, empty/duplicate `name`, uncompilable `regex`, or
  out-of-domain `severity`) fails with `{:error, :invalid_pattern_set}`.
  """
  @spec resolve([map()]) :: {:ok, t()} | {:error, :invalid_pattern_set}
  def resolve(entries) when is_list(entries) do
    with {:ok, validated} <- validate_entries(entries),
         grouped = Enum.group_by(validated, & &1.set),
         :ok <- unique_names(grouped) do
      {:ok, build_sets(grouped)}
    end
  end

  def resolve(_), do: {:error, :invalid_pattern_set}

  defp validate_entries(entries) do
    Enum.reduce_while(entries, {:ok, []}, fn entry, {:ok, acc} ->
      case validate_entry(entry) do
        {:ok, normalized} -> {:cont, {:ok, [normalized | acc]}}
        :error -> {:halt, {:error, :invalid_pattern_set}}
      end
    end)
  end

  defp validate_entry(entry) when is_map(entry) do
    with {:ok, set} <- fetch_set(entry),
         {:ok, name} <- fetch_name(entry),
         {:ok, regex} <- fetch_regex(entry),
         {:ok, severity} <- fetch_severity(entry) do
      {:ok,
       %{
         set: set,
         name: name,
         regex: regex,
         severity: severity,
         replacement_hint: get(entry, "replacement_hint"),
         max_match_bytes: max_match_bytes(entry),
         prefilter: prefilter(entry)
       }}
    else
      _ -> :error
    end
  end

  defp validate_entry(_), do: :error

  defp fetch_set(entry) do
    Map.fetch(@set_of, get(entry, "set"))
  end

  defp fetch_name(entry) do
    case get(entry, "name") do
      name when is_binary(name) and name != "" -> {:ok, name}
      _ -> :error
    end
  end

  defp fetch_regex(entry) do
    with source when is_binary(source) <- get(entry, "regex"),
         {:ok, regex} <- Regex.compile(source) do
      {:ok, regex}
    else
      _ -> :error
    end
  end

  defp fetch_severity(entry) do
    case get(entry, "severity") do
      nil -> {:ok, @default_severity}
      value -> Map.fetch(@severity_of, value)
    end
  end

  defp max_match_bytes(entry) do
    case get(entry, "max_match_bytes") do
      value when is_integer(value) and value >= 1 and value <= @max_match_bytes_limit -> value
      _ -> @default_max_match_bytes
    end
  end

  defp prefilter(entry) do
    case get(entry, "prefilter") do
      list when is_list(list) -> Enum.filter(list, &is_binary/1)
      _ -> []
    end
  end

  defp unique_names(grouped) do
    if Enum.all?(grouped, fn {_, entries} -> unique?(entries) end),
      do: :ok,
      else: {:error, :invalid_pattern_set}
  end

  defp unique?(entries) do
    names = Enum.map(entries, & &1.name)
    length(names) == length(Enum.uniq(names))
  end

  defp build_sets(grouped) do
    defaults = built_in()

    Map.new(@sets, fn set ->
      {set, set_or_default(grouped, set, defaults)}
    end)
  end

  defp set_or_default(grouped, set, defaults) do
    case Map.get(grouped, set) do
      nil -> Map.fetch!(defaults, set)
      entries -> Enum.map(entries, &compile_entry(&1, set))
    end
  end

  defp compile_entry(entry, :secret) do
    %{
      name: entry.name,
      category: :secret,
      severity: entry.severity,
      regex: entry.regex,
      replacement_hint: entry.replacement_hint,
      max_match_bytes: entry.max_match_bytes,
      set: :secret
    }
  end

  # Injection/poisoning entries take the `SigilGuard.Quarantine` indicator shape.
  defp compile_entry(entry, _) do
    %{id: entry.name, severity: entry.severity, prefilter: entry.prefilter, pattern: entry.regex}
  end

  defp get(entry, key), do: Map.get(entry, key) || Map.get(entry, String.to_existing_atom(key))
end
