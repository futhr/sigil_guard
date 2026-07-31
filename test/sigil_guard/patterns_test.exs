defmodule SigilGuard.PatternsTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Patterns

  describe "max_match_bytes (boundary policy holdback)" do
    test "built-in patterns declare the documented bounds" do
      bounds = Map.new(Patterns.built_in(), &{&1.name, &1.max_match_bytes})

      assert bounds["aws_access_key"] == 20
      assert bounds["private_key"] == 40

      for name <- ["generic_api_key", "bearer_token", "database_uri", "generic_secret"] do
        assert bounds[name] == 256, name
      end
    end

    test "a declared bundle bound within 1..4096 is used" do
      [pattern] =
        Patterns.compile([
          %{name: "x", category: "test", severity: :low, pattern: "x", max_match_bytes: 512}
        ])

      assert pattern.max_match_bytes == 512
    end

    test "an absent, out-of-range, or non-integer bound defaults to 256" do
      for bad <- [nil, 0, -1, 4097, "512", 12.5] do
        raw = %{name: "x", category: "test", severity: :low, pattern: "x"}
        raw = if bad == nil, do: raw, else: Map.put(raw, :max_match_bytes, bad)
        [pattern] = Patterns.compile([raw])
        assert pattern.max_match_bytes == 256, inspect(bad)
      end
    end

    test "largest_max_match_bytes returns the maximum, defaulting when empty" do
      assert Patterns.largest_max_match_bytes(Patterns.built_in()) == 256
      assert Patterns.largest_max_match_bytes([]) == 256

      patterns =
        Patterns.compile([
          %{name: "a", category: "t", severity: :low, pattern: "a", max_match_bytes: 100},
          %{name: "b", category: "t", severity: :low, pattern: "b", max_match_bytes: 4096}
        ])

      assert Patterns.largest_max_match_bytes(patterns) == 4096
    end
  end

  describe "built_in/0" do
    test "returns a list of compiled patterns" do
      patterns = Patterns.built_in()

      assert is_list(patterns)
      assert length(patterns) == 6

      for pattern <- patterns do
        assert is_binary(pattern.name)
        # Built-in secret patterns carry the closed :secret category atom.
        assert pattern.category == :secret
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

    test "skips malformed pattern entries without raising" do
      raw = [
        %{"name" => "good", "regex" => "GOOD", "category" => "test", "severity" => "low"},
        %{"name" => "missing_regex"},
        "not a map"
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

    test "skips patterns with unknown string severity" do
      raw = [%{"name" => "s", "pattern" => "s", "severity" => "extreme"}]
      assert [] = Patterns.compile(raw)
    end

    test "skips patterns with unknown atom severity" do
      raw = [%{name: "s", pattern: "s", severity: :critical}]
      assert [] = Patterns.compile(raw)
    end

    test "does not let fallbacks mask explicit malformed pattern fields" do
      raw = [
        %{
          :name => "masked",
          :pattern => false,
          "regex" => "MASKED_\\w+",
          :severity => false,
          "severity" => "high"
        },
        %{
          :name => false,
          "name" => "fallback_name",
          :category => false,
          "category" => "fallback_category",
          :severity => false,
          "severity" => "high",
          :pattern => "VISIBLE_\\w+"
        }
      ]

      assert [] = Patterns.compile(raw)
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

    test "returns error for malformed pattern entries" do
      assert {:error, :invalid_pattern_format} =
               Patterns.parse_bundle(%{"patterns" => [%{"name" => "missing_regex"}]})

      assert {:error, :invalid_pattern_format} =
               Patterns.parse_bundle(%{"patterns" => ["not_a_map"]})
    end

    test "returns error for explicit malformed pattern metadata" do
      for pattern <- [
            %{"name" => false, "regex" => "x"},
            %{"category" => false, "regex" => "x"},
            %{"replacement_hint" => false, "regex" => "x"},
            %{"severity" => "critical", "regex" => "x"},
            %{"severity" => false, "regex" => "x"}
          ] do
        assert {:error, :invalid_pattern_format} =
                 Patterns.parse_bundle(%{"patterns" => [pattern]})
      end
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
