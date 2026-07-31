defmodule SigilGuard.BoundaryPolicy.FileTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.BoundaryPolicy.Contract
  alias SigilGuard.BoundaryPolicy.File, as: PolicyFile
  alias SigilGuard.RepoPolicy

  @invalid_root SigilGuard.FixturePath.path("boundary_policy/invalid")

  describe "parse/1 success" do
    test "parses version, rules, folded matchers, contracts, and repo" do
      policy = """
      # a comment
      version 3

      [rules]
      block sensitivity:private zone:untrusted sink:external,network
      confirm trust:high sink:external
        effect:write   # inline comment
      default confirm

      [contracts]
      contract sink:external max_size:1024

      [repo]
      block secrets/**
      allow **
      """

      assert {:ok, compiled} = PolicyFile.parse(policy)
      assert compiled.default == :confirm

      assert [block_rule, confirm_rule] = compiled.rules
      assert block_rule.id == "line_5"
      assert block_rule.decision == :block

      assert block_rule.matchers == %{
               "sensitivity" => ["private"],
               "zone" => ["untrusted"],
               "sink" => ["external", "network"]
             }

      # The whitespace-continuation line folds into the confirm rule.
      assert confirm_rule.id == "line_6"
      assert confirm_rule.matchers["effect"] == ["write"]
      assert confirm_rule.matchers["trust"] == ["high"]

      assert compiled.contracts == %{
               "external" => %Contract{max_size: 1024, credential_transform: :mask}
             }

      assert %RepoPolicy{} = compiled.repo
    end

    test "accepts a version-only file and an absent default" do
      assert {:ok, %PolicyFile{rules: [], default: nil, contracts: contracts, repo: nil}} =
               PolicyFile.parse("version 3\n")

      assert contracts == %{}
    end

    test "accepts wildcard and exact string matchers" do
      assert {:ok, compiled} =
               PolicyFile.parse("version 3\n[rules]\nallow tool:* actor:svc:bot source:repo\n")

      rule = hd(compiled.rules)
      assert rule.matchers == %{"tool" => ["*"], "actor" => ["svc:bot"], "source" => ["repo"]}
    end

    test "rule ids track the first physical line of each logical line" do
      assert {:ok, compiled} =
               PolicyFile.parse("version 3\n[rules]\nblock trust:low\nconfirm trust:high\n")

      assert Enum.map(compiled.rules, & &1.id) == ["line_3", "line_4"]
    end
  end

  describe "parse/1 grammar errors" do
    # boundary policy: invalid/ holds one minimal file per parse-error atom. Fixtures
    # named after a contract atom fail with that atom; the rest are grammar
    # violations that all fail :invalid_policy_file.
    @atom_by_basename %{
      "invalid_output_contract" => :invalid_output_contract,
      "unknown_transform" => :unknown_transform
    }

    test "every invalid fixture fails with its named parse-error atom" do
      for path <- Path.wildcard(Path.join(@invalid_root, "*.policy")) do
        expected =
          Map.get(@atom_by_basename, Path.basename(path, ".policy"), :invalid_policy_file)

        assert PolicyFile.parse(File.read!(path)) == {:error, expected}, Path.basename(path)
      end
    end

    test "files over 256 KiB fail :policy_too_large" do
      oversized = "version 3\n" <> String.duplicate("x", 256 * 1024)
      assert PolicyFile.parse(oversized) == {:error, :policy_too_large}
    end

    test "a non-binary input fails :invalid_policy_file" do
      assert PolicyFile.parse(:nope) == {:error, :invalid_policy_file}
    end

    test "a bad repo body fails :invalid_policy_file" do
      assert PolicyFile.parse("version 3\n[repo]\ngibberish line\n") ==
               {:error, :invalid_policy_file}
    end

    test "an empty or comment-only file has no version line" do
      assert PolicyFile.parse("") == {:error, :invalid_policy_file}
      assert PolicyFile.parse("# just a comment\n") == {:error, :invalid_policy_file}
    end

    test "content outside a section fails" do
      assert PolicyFile.parse("version 3\nblock trust:low\n") == {:error, :invalid_policy_file}
    end

    test "a duplicated [repo] section fails" do
      assert PolicyFile.parse("version 3\n[repo]\nallow **\n[repo]\nblock **\n") ==
               {:error, :invalid_policy_file}
    end

    test "a default with an unknown decision fails" do
      assert PolicyFile.parse("version 3\n[rules]\ndefault maybe\n") ==
               {:error, :invalid_policy_file}
    end

    test "a matcher without a colon or with an empty value fails" do
      assert PolicyFile.parse("version 3\n[rules]\nblock trustlow\n") ==
               {:error, :invalid_policy_file}

      assert PolicyFile.parse("version 3\n[rules]\nblock trust:\n") ==
               {:error, :invalid_policy_file}
    end
  end
end
