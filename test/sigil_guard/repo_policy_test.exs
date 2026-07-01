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

    test "rejects absolute and traversal path patterns" do
      assert {:error, {:absolute_path_pattern, 0}} =
               RepoPolicy.compile(%{rules: [%{decision: :allow, paths: ["/etc/passwd"]}]})

      assert {:error, {:path_traversal_pattern, 0}} =
               RepoPolicy.compile(%{rules: [%{decision: :allow, paths: ["../secrets"]}]})
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
