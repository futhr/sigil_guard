defmodule SigilGuard.PatternSetsTest do
  use ExUnit.Case, async: true

  alias SigilGuard.PatternSets

  defp entry(over) do
    Map.merge(%{"set" => "secret", "name" => "p", "regex" => "abc"}, Map.new(over))
  end

  defp ids(list, key), do: Enum.map(list, &Map.fetch!(&1, key))

  describe "built_in/0" do
    test "returns the three sets in consumer-ready shapes" do
      sets = PatternSets.built_in()

      assert length(sets.secret) == 6
      assert length(sets.injection) == 6
      assert length(sets.poisoning) == 1

      assert %{name: _, category: :secret, regex: %Regex{}, set: :secret} = hd(sets.secret)
      assert %{id: _, severity: _, prefilter: _, pattern: %Regex{}} = hd(sets.injection)
    end
  end

  describe "resolve/1 override semantics" do
    test "an empty list resolves to every built-in default" do
      assert {:ok, sets} = PatternSets.resolve([])
      built_in = PatternSets.built_in()
      assert ids(sets.secret, :name) == ids(built_in.secret, :name)
      assert ids(sets.injection, :id) == ids(built_in.injection, :id)
      assert ids(sets.poisoning, :id) == ids(built_in.poisoning, :id)
    end

    test "each set is replaced independently; absent sets keep their default" do
      assert {:ok, sets} =
               PatternSets.resolve([
                 entry(%{"set" => "injection", "name" => "inj", "regex" => "danger"})
               ])

      assert length(sets.injection) == 1
      assert hd(sets.injection).id == "inj"
      # secret and poisoning untouched.
      built_in = PatternSets.built_in()
      assert ids(sets.secret, :name) == ids(built_in.secret, :name)
      assert ids(sets.poisoning, :id) == ids(built_in.poisoning, :id)
    end

    test "a secret entry compiles to the scanner pattern shape" do
      assert {:ok, %{secret: [pattern]}} =
               PatternSets.resolve([
                 entry(%{
                   "name" => "xk",
                   "regex" => "XK-[0-9]{6}",
                   "severity" => "high",
                   "replacement_hint" => "[XK]",
                   "max_match_bytes" => 32
                 })
               ])

      assert pattern.name == "xk"
      assert pattern.category == :secret
      assert pattern.set == :secret
      assert pattern.severity == :high
      assert pattern.replacement_hint == "[XK]"
      assert pattern.max_match_bytes == 32
      assert %Regex{} = pattern.regex
    end

    test "an injection entry compiles to the quarantine indicator shape" do
      assert {:ok, %{injection: [indicator]}} =
               PatternSets.resolve([
                 entry(%{
                   "set" => "injection",
                   "name" => "inj",
                   "regex" => "danger",
                   "prefilter" => ["danger"]
                 })
               ])

      assert indicator.id == "inj"
      assert indicator.severity == :medium
      assert indicator.prefilter == ["danger"]
      assert Regex.source(indicator.pattern) == "danger"
      assert Enum.sort(Map.keys(indicator)) == [:id, :pattern, :prefilter, :severity]
    end

    test "accepts atom-keyed entries and defaults prefilter/severity" do
      assert {:ok, %{poisoning: [indicator]}} =
               PatternSets.resolve([%{set: :poisoning, name: "pz", regex: "bad tool"}])

      assert indicator.id == "pz"
      assert indicator.severity == :medium
      assert indicator.prefilter == []
    end
  end

  describe "resolve/1 errors" do
    test "a non-list fails" do
      assert PatternSets.resolve(:nope) == {:error, :invalid_pattern_set}
    end

    test "an unknown set fails" do
      assert PatternSets.resolve([entry(%{"set" => "bogus"})]) == {:error, :invalid_pattern_set}
    end

    test "a non-map entry fails" do
      assert PatternSets.resolve(["not a map"]) == {:error, :invalid_pattern_set}
      assert PatternSets.resolve([entry(%{}), nil]) == {:error, :invalid_pattern_set}
    end

    test "a missing or empty name fails" do
      assert PatternSets.resolve([entry(%{"name" => ""})]) == {:error, :invalid_pattern_set}
      assert PatternSets.resolve([entry(%{"name" => 42})]) == {:error, :invalid_pattern_set}
    end

    test "a non-string or uncompilable regex fails" do
      assert PatternSets.resolve([entry(%{"regex" => "[invalid"})]) ==
               {:error, :invalid_pattern_set}

      assert PatternSets.resolve([entry(%{"regex" => 5})]) == {:error, :invalid_pattern_set}
    end

    test "an out-of-domain severity fails" do
      assert PatternSets.resolve([entry(%{"severity" => "critical"})]) ==
               {:error, :invalid_pattern_set}
    end

    test "a duplicate name within a set fails" do
      assert PatternSets.resolve([
               entry(%{"name" => "dup", "regex" => "a"}),
               entry(%{"name" => "dup", "regex" => "b"})
             ]) == {:error, :invalid_pattern_set}
    end

    test "the same name in different sets is allowed" do
      assert {:ok, _} =
               PatternSets.resolve([
                 entry(%{"set" => "secret", "name" => "shared", "regex" => "a"}),
                 entry(%{"set" => "injection", "name" => "shared", "regex" => "b"})
               ])
    end
  end
end
