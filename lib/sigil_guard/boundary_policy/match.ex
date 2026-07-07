defmodule SigilGuard.BoundaryPolicy.Match do
  @moduledoc """
  Match compiled `[rules]` against a `SigilGuard.Boundary` (SP.04).

  A rule matches when every matcher key matches (AND); a matcher key matches
  when the input field equals one of the rule's values (OR). An absent matcher
  key matches anything. `source`, `tool`, and `actor` accept `*`; `hits` and
  `indicator` use `none`/`any` over the categories present; `effect` intersects
  the tool's side-effect classes; `isolation` uses `absent` for a nil level.
  """

  alias SigilGuard.Boundary

  @doc """
  Return the rules from `rules` whose matchers all match `boundary`, in order.
  """
  @spec matching_rules([map()], Boundary.t()) :: [map()]
  def matching_rules(rules, %Boundary{} = boundary) do
    Enum.filter(rules, &rule_matches?(&1, boundary))
  end

  defp rule_matches?(%{matchers: matchers}, boundary) do
    Enum.all?(matchers, fn {key, values} -> matcher_matches?(key, values, boundary) end)
  end

  defp matcher_matches?("phase", values, b), do: to_string(b.phase) in values
  defp matcher_matches?("origin", values, b), do: present_in?(b.origin, values)
  defp matcher_matches?("sink", values, b), do: present_in?(b.sink, values)
  defp matcher_matches?("zone", values, b), do: present_in?(b.trust_zone, values)
  defp matcher_matches?("trust", values, b), do: present_in?(b.trust_level, values)
  defp matcher_matches?("sensitivity", values, b), do: present_in?(b.source_sensitivity, values)
  defp matcher_matches?("source", values, b), do: star_match?(str(b.source), values)
  defp matcher_matches?("tool", values, b), do: star_match?(tool_name(b), values)
  defp matcher_matches?("actor", values, b), do: star_match?(actor_id(b), values)
  defp matcher_matches?("isolation", values, b), do: isolation_match?(isolation(b), values)
  defp matcher_matches?("effect", values, b), do: intersects?(values, side_effects(b))
  defp matcher_matches?("hits", values, b), do: categories_match?(values, hit_categories(b))

  defp matcher_matches?("indicator", values, b),
    do: categories_match?(values, indicator_categories(b))

  defp matcher_matches?(_, _, _), do: false

  # -- Value comparisons ------------------------------------------------------

  defp present_in?(nil, _), do: false
  defp present_in?(value, values), do: str(value) in values

  defp star_match?(nil, _), do: false
  defp star_match?(value, values), do: "*" in values or value in values

  defp isolation_match?(nil, values), do: "absent" in values
  defp isolation_match?(level, values), do: str(level) in values

  defp intersects?(values, present), do: Enum.any?(values, &(&1 in present))

  defp categories_match?(values, present) do
    Enum.any?(values, &category_value_matches?(&1, present))
  end

  defp category_value_matches?("none", present), do: present == []
  defp category_value_matches?("any", present), do: present != []
  defp category_value_matches?(value, present), do: value in present

  # -- Field extraction -------------------------------------------------------

  defp isolation(%Boundary{sandbox: sandbox}) when is_map(sandbox) do
    fetch(sandbox, "isolation_level")
  end

  defp isolation(_), do: nil

  defp side_effects(%Boundary{tool: tool}) when is_map(tool) do
    tool
    |> fetch("side_effects")
    |> List.wrap()
    |> Enum.map(&str/1)
  end

  defp side_effects(_), do: []

  defp tool_name(%Boundary{tool: tool}) when is_map(tool), do: str(fetch(tool, "name"))
  defp tool_name(_), do: nil

  defp actor_id(%Boundary{actor: actor}) when is_map(actor), do: str(fetch(actor, "id"))
  defp actor_id(_), do: nil

  defp hit_categories(%Boundary{hits: hits}), do: categories(hits)
  defp indicator_categories(%Boundary{indicators: indicators}), do: categories(indicators)

  defp categories(entries) when is_list(entries) do
    entries
    |> Enum.map(&entry_category/1)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end

  defp categories(_), do: []

  defp entry_category(entry) when is_map(entry), do: str(fetch(entry, "category"))
  defp entry_category(_), do: nil

  defp fetch(map, key), do: Map.get(map, key) || Map.get(map, String.to_existing_atom(key))

  defp str(nil), do: nil
  defp str(value) when is_atom(value), do: Atom.to_string(value)
  defp str(value) when is_binary(value), do: value
  defp str(_), do: nil
end
