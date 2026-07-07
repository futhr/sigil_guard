defmodule Mix.Tasks.Sigil.DocsLintTest do
  @moduledoc false

  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Mix.Tasks.Sigil.DocsLint

  describe "run/1" do
    test "prints success for a clean docs tree" do
      root =
        fixture_root(%{
          "README.md" => "Public docs\n",
          "docs/specs/SP.01-example.md" => front_matter("SP.01"),
          "docs/tasks/sigil-tasks.md" => "- [ ] M1.01 Uses `SP.01`.\n"
        })

      output =
        capture_io(fn ->
          File.cd!(root, fn ->
            assert :ok = DocsLint.run([])
          end)
        end)

      assert output =~ "Docs lint passed"
    end

    test "rejects command line arguments" do
      assert_raise Mix.Error, ~r/does not accept options/, fn ->
        DocsLint.run(["--bad"])
      end
    end

    test "raises with formatted findings" do
      root =
        fixture_root(%{
          "README.md" => "Do not publish _sigil examples here.\n",
          "docs/specs/SP.01-example.md" => front_matter("SP.01"),
          "docs/tasks/sigil-tasks.md" => "- [ ] M1.01 Uses `SP.01`.\n"
        })

      assert_raise Mix.Error, ~r/README\.md:1: old_vocabulary/, fn ->
        File.cd!(root, fn -> DocsLint.run([]) end)
      end
    end
  end

  describe "lint/1" do
    test "accepts a clean docs tree" do
      root =
        fixture_root(%{
          "README.md" => "Public docs\n",
          "CONTRIBUTING.md" => "Contributing\n",
          "docs/README.md" => "Architecture\n",
          "docs/specs/README.md" => "[`SP.01`](SP.01-example.md)\n",
          "docs/specs/SP.01-example.md" => front_matter("SP.01"),
          "docs/tasks/sigil-tasks.md" => "- [ ] M1.01 Uses `SP.01`.\n"
        })

      assert :ok = DocsLint.lint(root: root)
    end

    test "reports spec ids missing task references" do
      root =
        fixture_root(%{
          "docs/specs/SP.01-example.md" => front_matter("SP.01"),
          "docs/tasks/sigil-tasks.md" => "# Tasks\n"
        })

      assert {:error, [finding]} = DocsLint.lint(root: root)
      assert finding.check == :spec_drift
      assert finding.message == "SP.01 has no task reference"
    end

    test "reports spec ids when the task file is missing" do
      root =
        fixture_root(%{
          "docs/specs/SP.01-example.md" => front_matter("SP.01")
        })

      assert {:error, [finding]} = DocsLint.lint(root: root)
      assert finding.check == :spec_drift
      assert finding.message == "SP.01 has no task reference"
    end

    test "reports task ids missing spec files" do
      root =
        fixture_root(%{
          "docs/tasks/sigil-tasks.md" => "- [ ] M1.01 Uses `SP.99`.\n"
        })

      assert {:error, [finding]} = DocsLint.lint(root: root)
      assert finding.check == :spec_drift
      assert finding.message == "SP.99 has no spec file"
    end

    test "reports forbidden inspiration-project terms from the private list" do
      root =
        fixture_root(%{
          "docs/specs/SP.01-example.md" => front_matter("SP.01") <> "blocked-marker\n",
          "docs/tasks/sigil-tasks.md" => "- [ ] M1.01 Uses `SP.01`.\n"
        })

      assert {:error, [finding]} = DocsLint.lint(root: root, forbidden_terms: ["blocked-marker"])
      assert finding.check == :forbidden_term
      assert finding.path == "docs/specs/SP.01-example.md"
    end

    test "reports known-dead public protocol or registry URLs from the private list" do
      root =
        fixture_root(%{
          "docs/specs/SP.01-example.md" => front_matter("SP.01") <> "https://dead.example/path\n",
          "docs/tasks/sigil-tasks.md" => "- [ ] M1.01 Uses `SP.01`.\n"
        })

      assert {:error, [finding]} =
               DocsLint.lint(root: root, dead_urls: ["https://dead.example/path"])

      assert finding.check == :dead_url
    end

    test "reports stale three-digit research and spec ids" do
      root =
        fixture_root(%{
          "docs/specs/SP.01-example.md" => front_matter("SP.01") <> "See SP.001 and R.002.\n",
          "docs/tasks/sigil-tasks.md" => "- [ ] M1.01 Uses `SP.01`.\n"
        })

      assert {:error, findings} = DocsLint.lint(root: root)
      assert Enum.map(findings, & &1.check) == [:stale_id, :stale_id]

      assert Enum.map(findings, & &1.message) == [
               "stale three-digit id SP.001",
               "stale three-digit id R.002"
             ]
    end

    test "reports local filesystem links" do
      root =
        fixture_root(%{
          "docs/specs/SP.01-example.md" =>
            front_matter("SP.01") <> "[local](file:///tmp/example)\n",
          "docs/tasks/sigil-tasks.md" => "- [ ] M1.01 Uses `SP.01`.\n"
        })

      assert {:error, [finding]} = DocsLint.lint(root: root)
      assert finding.check == :local_filesystem_link
    end

    test "reports old wire and config vocabulary in public docs" do
      root =
        fixture_root(%{
          "README.md" => "Do not publish _sigil examples here.\n",
          "docs/specs/SP.01-example.md" => front_matter("SP.01"),
          "docs/tasks/sigil-tasks.md" => "- [ ] M1.01 Uses `SP.01`.\n"
        })

      assert {:error, [finding]} = DocsLint.lint(root: root)
      assert finding.check == :old_vocabulary
      assert finding.path == "README.md"
    end

    test "exempts migration docs and historical fixtures from old vocabulary checks" do
      root =
        fixture_root(%{
          "README.md" => "Public docs\n",
          "MIGRATING-1.0.md" => "_sigil migration note\n",
          "test/fixtures/historical/example.md" => "_sigil fixture note\n",
          "docs/specs/SP.01-example.md" => front_matter("SP.01"),
          "docs/tasks/sigil-tasks.md" => "- [ ] M1.01 Uses `SP.01`.\n"
        })

      assert :ok = DocsLint.lint(root: root)
    end
  end

  defp fixture_root(files) do
    root = Path.join(System.tmp_dir!(), "sigil_docs_lint_#{System.unique_integer([:positive])}")
    File.rm_rf!(root)

    Enum.each(files, fn {relative_path, content} ->
      path = Path.join(root, relative_path)
      File.mkdir_p!(Path.dirname(path))
      File.write!(path, content)
    end)

    root
  end

  defp front_matter(id) do
    """
    ---
    id: "#{id}"
    ---

    # #{id}
    """
  end
end
