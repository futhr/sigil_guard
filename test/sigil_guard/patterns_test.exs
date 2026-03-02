defmodule SigilGuard.PatternsTest do
  @moduledoc """
  Tests for `SigilGuard.Patterns`.

  Validates the built-in pattern catalogue: structure, required fields,
  regex compilation, and detection accuracy for each pattern category.
  """

  use ExUnit.Case, async: true

  alias SigilGuard.Patterns

  describe "built_in/0" do
    test "returns a list of compiled patterns" do
      patterns = Patterns.built_in()

      assert is_list(patterns)
      assert length(patterns) == 6

      for pattern <- patterns do
        assert is_binary(pattern.name)
        assert is_binary(pattern.category)
        assert pattern.severity in [:low, :medium, :high]
        assert %Regex{} = pattern.regex
      end
    end

    test "includes expected pattern names" do
      names =
        Patterns.built_in()
        |> Enum.map(& &1.name)
        |> Enum.sort()

      assert names == [
               "aws_access_key",
               "bearer_token",
               "database_uri",
               "generic_api_key",
               "generic_secret",
               "private_key"
             ]
    end
  end

  describe "compile/1" do
    test "compiles patterns from atom-keyed maps" do
      raw = [
        %{name: "test", category: "custom", severity: :low, pattern: "foo\\d+"}
      ]

      assert [pattern] = Patterns.compile(raw)
      assert pattern.name == "test"
      assert Regex.match?(pattern.regex, "foo123")
    end

    test "compiles patterns from string-keyed maps (registry format)" do
      raw = [
        %{
          "name" => "registry_pat",
          "category" => "cred",
          "severity" => "high",
          "regex" => "BAR_\\w+"
        }
      ]

      assert [pattern] = Patterns.compile(raw)
      assert pattern.name == "registry_pat"
      assert pattern.severity == :high
    end

    test "skips patterns with invalid regex" do
      raw = [
        %{name: "good", category: "test", severity: :low, pattern: "valid"},
        %{name: "bad", category: "test", severity: :low, pattern: "[invalid"}
      ]

      assert [pattern] = Patterns.compile(raw)
      assert pattern.name == "good"
    end

    test "defaults severity to :medium when missing" do
      raw = [%{name: "no_sev", category: "test", pattern: "test"}]
      assert [pattern] = Patterns.compile(raw)
      assert pattern.severity == :medium
    end

    test "defaults name to unnamed when missing" do
      raw = [%{category: "test", pattern: "test"}]
      assert [pattern] = Patterns.compile(raw)
      assert pattern.name == "unnamed"
    end

    test ~s[compiles patterns with string "pattern" key (not "regex")] do
      raw = [
        %{
          "name" => "string_pat",
          "category" => "test",
          "severity" => "medium",
          "pattern" => "STR_\\d+"
        }
      ]

      assert [pattern] = Patterns.compile(raw)
      assert pattern.name == "string_pat"
      assert Regex.match?(pattern.regex, "STR_123")
    end

    test "includes replacement_hint from string-keyed map" do
      raw = [
        %{
          "name" => "hinted",
          "category" => "test",
          "severity" => "low",
          "regex" => "HINT_\\w+",
          "replacement_hint" => "[REPLACED]"
        }
      ]

      assert [pattern] = Patterns.compile(raw)
      assert pattern.replacement_hint == "[REPLACED]"
    end

    test "defaults category to unknown when missing" do
      raw = [%{name: "no_cat", pattern: "test"}]
      assert [pattern] = Patterns.compile(raw)
      assert pattern.category == "unknown"
    end

    test "parses all severity levels from strings" do
      for {severity_str, severity_atom} <- [
            {"low", :low},
            {"medium", :medium},
            {"high", :high}
          ] do
        raw = [%{"name" => "s", "pattern" => "s", "severity" => severity_str}]
        assert [pattern] = Patterns.compile(raw)
        assert pattern.severity == severity_atom
      end
    end

    test "defaults severity for unknown string severity" do
      raw = [%{"name" => "s", "pattern" => "s", "severity" => "extreme"}]
      assert [pattern] = Patterns.compile(raw)
      assert pattern.severity == :medium
    end
  end

  describe "parse_bundle/1" do
    test "extracts patterns from valid bundle" do
      bundle = %{
        "generated_at" => "2024-01-01T00:00:00Z",
        "count" => 2,
        "patterns" => [
          %{"name" => "p1", "regex" => "\\d+"},
          %{"name" => "p2", "regex" => "\\w+"}
        ]
      }

      assert {:ok, patterns} = Patterns.parse_bundle(bundle)
      assert length(patterns) == 2
    end

    test "returns error for missing patterns key" do
      assert {:error, :invalid_bundle_format} = Patterns.parse_bundle(%{"data" => []})
    end

    test "returns error for non-list patterns" do
      assert {:error, :invalid_bundle_format} =
               Patterns.parse_bundle(%{"patterns" => "not_a_list"})
    end

    test "returns error for non-map input" do
      assert {:error, :invalid_bundle_format} = Patterns.parse_bundle("string")
    end
  end

  describe "merge/2" do
    test "override patterns take precedence on name collision" do
      base =
        Patterns.compile([%{name: "shared", category: "base", severity: :low, pattern: "base"}])

      override =
        Patterns.compile([
          %{name: "shared", category: "override", severity: :high, pattern: "override"}
        ])

      merged = Patterns.merge(base, override)

      assert length(merged) == 1
      assert hd(merged).category == "override"
      assert hd(merged).severity == :high
    end

    test "includes non-colliding patterns from both lists" do
      base = Patterns.compile([%{name: "a", category: "base", severity: :low, pattern: "a"}])

      override =
        Patterns.compile([%{name: "b", category: "ext", severity: :medium, pattern: "b"}])

      merged = Patterns.merge(base, override)
      names = Enum.map(merged, & &1.name) |> Enum.sort()

      assert names == ["a", "b"]
    end

    test "empty override preserves base" do
      base = Patterns.built_in()
      merged = Patterns.merge(base, [])

      assert length(merged) == length(base)
    end

    test "empty base uses override" do
      override = Patterns.compile([%{name: "x", category: "test", severity: :low, pattern: "x"}])
      merged = Patterns.merge([], override)

      assert length(merged) == 1
    end
  end
end
