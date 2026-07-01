defmodule SigilGuard.RepoPolicyTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.RepoPolicy
  alias SigilGuard.RepoPolicy.Decision

  describe "compile/1" do
    test "compiles map policies with normalized rules" do
      assert {:ok, policy} =
               RepoPolicy.compile(%{
                 default: :require_approval,
                 rules: [
                   %{
                     id: "docs",
                     decision: "allow",
                     agents: ["did:web:codex"],
                     actions: ["modify"],
                     paths: ["README.md", "docs/**"]
                   }
                 ]
               })

      assert %RepoPolicy{} = policy
      assert policy.default == :require_approval
      assert [rule] = policy.rules
      assert rule.id == "docs"
      assert rule.decision == :allow
      assert rule.agents == ["did:web:codex"]
      assert rule.actions == ["modify"]
      assert rule.paths == ["README.md", "docs/**"]
    end

    test "accepts compiled and keyword policies with aliases and defaults" do
      assert {:ok, compiled} =
               RepoPolicy.compile(
                 default: :allowed,
                 rules: [
                   [
                     decision: :confirm,
                     agent: :codex,
                     action: "modify",
                     path: "docs/",
                     message: :review_docs
                   ]
                 ]
               )

      assert {:ok, ^compiled} = RepoPolicy.compile(compiled)
      assert compiled.default == :allow
      assert [rule] = compiled.rules
      assert rule.id == "rule_0"
      assert rule.decision == :require_approval
      assert rule.agents == ["codex"]
      assert rule.paths == ["docs/**"]
      assert rule.message == "review_docs"
    end

    test "rejects absolute and traversal path patterns" do
      assert {:error, {:absolute_path_pattern, 0}} =
               RepoPolicy.compile(%{rules: [%{decision: :allow, paths: ["/etc/passwd"]}]})

      assert {:error, {:path_traversal_pattern, 0}} =
               RepoPolicy.compile(%{rules: [%{decision: :allow, paths: ["../secrets"]}]})
    end

    test "rejects malformed policies and rules" do
      assert {:error, :invalid_policy} = RepoPolicy.compile(:bad)
      assert {:error, :invalid_rules} = RepoPolicy.compile(%{rules: :bad})
      assert {:error, {:invalid_rule, 0}} = RepoPolicy.compile(%{rules: [:bad]})
      assert {:error, {:invalid_decision, 0}} = RepoPolicy.compile(%{rules: [%{paths: ["*"]}]})
      assert {:error, :invalid_decision} = RepoPolicy.compile(%{default: false})
      assert {:error, :invalid_rules} = RepoPolicy.compile(%{rules: false})

      assert {:error, {:invalid_decision, 0}} =
               RepoPolicy.compile(%{rules: [%{decision: "nope", paths: ["*"]}]})

      assert {:error, {:invalid_matchers, 0}} =
               RepoPolicy.compile(%{rules: [%{decision: :allow, agents: [123], paths: ["*"]}]})

      assert {:error, {:missing_paths, 0}} =
               RepoPolicy.compile(%{rules: [%{decision: :allow, paths: []}]})

      assert {:error, {:invalid_path_pattern, 0}} =
               RepoPolicy.compile(%{rules: [%{decision: :allow, paths: [""]}]})

      assert {:error, {:invalid_rule_id, 0}} =
               RepoPolicy.compile(%{rules: [%{id: "", decision: :allow, paths: ["*"]}]})

      assert {:error, {:invalid_rule_id, 0}} =
               RepoPolicy.compile(%{rules: [%{id: false, decision: :allow, paths: ["*"]}]})
    end

    test "does not let fallback defaults mask explicit invalid policy fields" do
      valid_rule = %{decision: :allow, paths: ["*"]}

      invalid_default = %{
        "default" => false,
        default: :allow
      }

      assert {:error, :invalid_decision} = RepoPolicy.compile(invalid_default)

      invalid_rules = %{
        "rules" => false,
        rules: [valid_rule]
      }

      assert {:error, :invalid_rules} = RepoPolicy.compile(invalid_rules)

      for {field, alias_field, reason} <- [
            {"agents", "agent", :invalid_matchers},
            {"actions", "action", :invalid_matchers},
            {"paths", "path", :missing_paths}
          ] do
        rule =
          valid_rule
          |> Map.put(field, false)
          |> Map.put(alias_field, "*")

        assert {:error, {^reason, 0}} = RepoPolicy.compile(%{rules: [rule]})
      end
    end
  end

  describe "parse/1" do
    test "parses line-oriented repo policies" do
      text = """
      # comments are ignored
      default require_approval
      allow agent:did:web:codex action:modify README.md docs/**
      block agent:* priv/secrets/**
      """

      assert {:ok, policy} = RepoPolicy.parse(text)
      assert policy.default == :require_approval
      assert Enum.map(policy.rules, & &1.id) == ["line_3", "line_4"]
      assert hd(policy.rules).agents == ["did:web:codex"]
      assert hd(policy.rules).actions == ["modify"]
    end

    test "returns parse errors for invalid defaults and malformed rules" do
      assert {:error, :invalid_decision} = RepoPolicy.parse("default nope\n")
      assert {:error, {:invalid_decision, 0}} = RepoPolicy.parse("nope docs/**\n")
      assert {:error, {:invalid_matchers, 0}} = RepoPolicy.parse("allow agent: docs/**\n")
      assert {:error, {:missing_paths, 0}} = RepoPolicy.parse("allow agent:*\n")
    end
  end

  describe "load/2" do
    setup do
      dir =
        Path.join(
          System.tmp_dir!(),
          "sigil_guard_repo_policy_test_#{System.unique_integer([:positive])}"
        )

      File.mkdir_p!(dir)
      on_exit(fn -> File.rm_rf!(dir) end)

      {:ok, dir: dir}
    end

    test "loads the first deterministic policy file from a repo root", %{dir: dir} do
      File.write!(
        Path.join(dir, "SIGIL_POLICY"),
        """
        default require_approval
        allow agent:did:web:codex action:modify docs/**
        """
      )

      assert {:ok, policy} = RepoPolicy.load(dir)

      decision =
        RepoPolicy.evaluate(policy,
          agent: "did:web:codex",
          action: "modify",
          changed_paths: ["docs/guide.md"]
        )

      assert decision.verdict == :allow
      assert decision.matched_rule_ids == ["line_2"]
    end

    test "honors candidate order without escaping the repo root", %{dir: dir} do
      github_dir = Path.join(dir, ".github")
      File.mkdir_p!(github_dir)

      File.write!(Path.join(dir, ".sigil-policy"), "default block\n")
      File.write!(Path.join(github_dir, "sigil-policy"), "default allow\n")

      assert {:ok, path} = RepoPolicy.find_file(dir)
      assert path == Path.join(dir, ".sigil-policy")

      assert {:error, :policy_path_traversal} =
               RepoPolicy.find_file(dir, candidates: ["../SIGIL_POLICY"])

      assert {:error, :absolute_policy_path} =
               RepoPolicy.find_file(dir, candidates: [Path.join(dir, ".sigil-policy")])
    end

    test "accepts a single candidate path and rejects invalid candidate sets", %{dir: dir} do
      File.write!(Path.join(dir, ".sigil-policy"), "default allow\n")

      assert {:ok, path} = RepoPolicy.find_file(dir, candidates: ".sigil-policy")
      assert path == Path.join(dir, ".sigil-policy")

      assert {:error, :missing_policy_paths} = RepoPolicy.find_file(dir, candidates: [])
      assert {:error, :invalid_policy_paths} = RepoPolicy.find_file(dir, candidates: :bad)
      assert {:error, :invalid_policy_path} = RepoPolicy.find_file(dir, candidates: [""])
      assert {:error, :invalid_policy_path} = RepoPolicy.find_file(dir, candidates: [123])
    end

    test "returns not_found when no candidate exists", %{dir: dir} do
      assert {:error, :not_found} = RepoPolicy.load(dir)
    end

    test "rejects oversized or invalid policy files", %{dir: dir} do
      path = Path.join(dir, "SIGIL_POLICY")
      File.write!(path, "default allow\n")

      assert {:error, :policy_too_large} = RepoPolicy.load_file(path, max_bytes: 4)
      assert {:error, :invalid_max_bytes} = RepoPolicy.load_file(path, max_bytes: -1)
      assert {:error, {:invalid_policy_file, :directory}} = RepoPolicy.load_file(dir)
    end

    test "returns file read and parse errors", %{dir: dir} do
      missing = Path.join(dir, "missing")
      invalid = Path.join(dir, "SIGIL_POLICY")
      File.write!(invalid, "default nope\n")

      assert {:error, :enoent} = RepoPolicy.load_file(missing)
      assert {:error, :invalid_decision} = RepoPolicy.load_file(invalid)
    end
  end

  describe "evaluate/2" do
    test "allows when every changed path is explicitly allowed" do
      policy = compile!(rules: [rule("docs", :allow, ["README.md", "docs/**"])])

      decision =
        RepoPolicy.evaluate(policy,
          agent: "did:web:codex",
          action: "modify",
          changed_paths: ["README.md", "docs/usage/setup.md"]
        )

      assert %Decision{} = decision
      assert decision.verdict == :allow
      assert decision.matched_rule_ids == ["docs"]
      assert decision.unmatched_paths == []
      assert byte_size(decision.digest) == 64
    end

    test "requires approval for unmatched paths by default" do
      policy = compile!(rules: [rule("docs", :allow, ["docs/**"])])

      decision =
        RepoPolicy.evaluate(policy,
          agent: "did:web:codex",
          action: "modify",
          changed_paths: ["docs/guide.md", "lib/sigil_guard.ex"]
        )

      assert decision.verdict == :require_approval
      assert decision.matched_rule_ids == ["docs"]
      assert decision.unmatched_paths == ["lib/sigil_guard.ex"]
      assert decision.reason =~ "unmatched"
    end

    test "block wins over allow for any changed path" do
      policy =
        compile!(
          rules: [
            rule("all-docs", :allow, ["docs/**"]),
            rule("locked-docs", :block, ["docs/private/**"])
          ]
        )

      decision =
        RepoPolicy.evaluate(policy,
          agent: "did:web:codex",
          action: "modify",
          changed_paths: ["docs/private/runbook.md"]
        )

      assert decision.verdict == :block
      assert decision.matched_rule_ids == ["all-docs", "locked-docs"]
      assert decision.reason =~ "locked-docs"
    end

    test "matches exact agents and actions" do
      policy =
        compile!(
          rules: [
            %{
              id: "codex-docs",
              decision: :allow,
              agents: ["did:web:codex"],
              actions: ["modify"],
              paths: ["docs/**"]
            }
          ]
        )

      allowed =
        RepoPolicy.evaluate(policy,
          agent: "did:web:codex",
          action: "modify",
          changed_paths: ["docs/a.md"]
        )

      other_agent =
        RepoPolicy.evaluate(policy,
          agent: "did:web:other",
          action: "modify",
          changed_paths: ["docs/a.md"]
        )

      other_action =
        RepoPolicy.evaluate(policy,
          agent: "did:web:codex",
          action: "delete",
          changed_paths: ["docs/a.md"]
        )

      assert allowed.verdict == :allow
      assert other_agent.verdict == :require_approval
      assert other_action.verdict == :require_approval
    end

    test "blocks invalid changed paths before matching rules" do
      policy = compile!(default: :allow, rules: [])

      decision =
        RepoPolicy.evaluate(policy,
          agent: "did:web:codex",
          action: "modify",
          changed_paths: ["../../etc/passwd"]
        )

      assert decision.verdict == :block
      assert decision.reason =~ "path_traversal"
      assert decision.matched_rule_ids == []
    end

    test "uses default decisions for empty and unmatched path sets" do
      allow_default = compile!(default: :allow, rules: [])
      block_default = compile!(default: :block, rules: [])

      allowed =
        RepoPolicy.evaluate(allow_default,
          agent: "did:web:codex",
          action: "modify",
          changed_paths: ["src/new.ex"]
        )

      blocked_empty =
        RepoPolicy.evaluate(block_default,
          agent: "did:web:codex",
          action: "modify",
          changed_paths: []
        )

      assert allowed.verdict == :allow
      assert allowed.reason =~ "default allowed"
      assert allowed.unmatched_paths == ["src/new.ex"]
      assert blocked_empty.verdict == :block
      assert blocked_empty.reason =~ "blocked"
    end

    test "matches wildcard agents when context identity is missing" do
      policy =
        compile!(
          default: :block,
          rules: [
            %{
              id: "public-docs",
              decision: :allow,
              agents: ["*"],
              actions: ["modify"],
              paths: ["docs/**"]
            }
          ]
        )

      decision = RepoPolicy.evaluate(policy, action: "modify", changed_paths: ["docs/index.md"])

      assert decision.verdict == :allow
      assert decision.agent == nil
      assert decision.matched_rule_ids == ["public-docs"]
    end

    test "normalizes context aliases, atoms, duplicates, separators, and dot paths" do
      policy =
        compile!(
          default: :block,
          rules: [
            %{
              id: :src,
              decision: :allow,
              agents: ["runner"],
              actions: ["modify"],
              paths: ["src/*.ex", "docs/??.md", "."]
            }
          ]
        )

      src =
        RepoPolicy.evaluate(policy,
          identity: :runner,
          action: :modify,
          changed_files: ["src\\.\\main.ex", "src/main.ex"]
        )

      docs =
        RepoPolicy.evaluate(policy,
          actor: "runner",
          action: "modify",
          files: ["docs/ab.md"]
        )

      dot =
        RepoPolicy.evaluate(policy,
          agent: "runner",
          action: "modify",
          paths: ["."]
        )

      single =
        RepoPolicy.evaluate(policy,
          agent: "runner",
          action: "modify",
          changed_paths: "src/main.ex"
        )

      assert src.verdict == :allow
      assert src.changed_paths == ["src/main.ex"]
      assert docs.verdict == :allow
      assert dot.verdict == :allow
      assert single.verdict == :allow
    end

    test "does not let atom fallbacks mask explicit invalid string context fields" do
      policy =
        compile!(
          default: :block,
          rules: [
            %{
              id: "src",
              decision: :allow,
              agents: ["runner"],
              actions: ["modify"],
              paths: ["src/**"]
            }
          ]
        )

      decision =
        RepoPolicy.evaluate(policy, %{
          "agent" => false,
          :agent => "runner",
          "action" => false,
          :action => "modify",
          "changed_paths" => false,
          :changed_paths => ["src/main.ex"]
        })

      assert decision.verdict == :block
      assert decision.agent == nil
      assert decision.action == "modify"
      assert decision.changed_paths == []
    end

    test "matches globstar across zero or more path segments" do
      policy =
        compile!(
          rules: [
            %{
              id: "nested",
              decision: :allow,
              agents: ["*"],
              actions: ["*"],
              paths: ["apps/**/mix.exs"]
            }
          ]
        )

      root = RepoPolicy.evaluate(policy, changed_paths: ["apps/mix.exs"])
      nested = RepoPolicy.evaluate(policy, changed_paths: ["apps/core/service/mix.exs"])
      non_match = RepoPolicy.evaluate(policy, changed_paths: ["apps/core/service/config.exs"])

      assert root.verdict == :allow
      assert nested.verdict == :allow
      assert non_match.verdict == :require_approval
      assert non_match.unmatched_paths == ["apps/core/service/config.exs"]
    end

    test "blocks invalid changed-path forms before rule evaluation" do
      policy = compile!(default: :allow, rules: [])

      for {paths, reason} <- [
            {"/tmp/file", "absolute_changed_path"},
            {[""], "invalid_changed_path"},
            {[123], "invalid_changed_path"},
            {:bad, "invalid_changed_paths"}
          ] do
        decision =
          RepoPolicy.evaluate(policy, agent: "runner", action: "modify", changed_paths: paths)

        assert decision.verdict == :block
        assert decision.reason =~ reason
      end
    end

    test "uses default action and nil identity for malformed contexts" do
      policy = compile!(default: :allow, rules: [])

      decision = RepoPolicy.evaluate(policy, :bad_context)

      assert decision.verdict == :allow
      assert decision.agent == nil
      assert decision.action == "modify"
      assert decision.changed_paths == []
    end
  end

  describe "digest/1" do
    test "produces stable canonical policy digests" do
      policy = compile!(rules: [rule("docs", :allow, ["docs/**"])])

      assert RepoPolicy.canonical_bytes(policy) == RepoPolicy.canonical_bytes(policy)
      assert RepoPolicy.digest(policy) == RepoPolicy.digest(policy)
      assert byte_size(RepoPolicy.digest(policy)) == 64
    end
  end

  defp compile!(policy) do
    {:ok, compiled} = RepoPolicy.compile(policy)
    compiled
  end

  defp rule(id, decision, paths) do
    %{
      id: id,
      decision: decision,
      agents: ["did:web:codex"],
      actions: ["modify"],
      paths: paths
    }
  end
end
