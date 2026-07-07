defmodule SigilGuard.BoundaryPolicy.LoadTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.BoundaryPolicy.File, as: PolicyFile

  @policy "version 3\n[rules]\nblock trust:low\n"

  setup do
    root = Path.join(System.tmp_dir!(), "sigil-policy-load-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf!(root) end)
    %{root: root}
  end

  defp write(root, relative, contents) do
    path = Path.join(root, relative)
    File.mkdir_p!(Path.dirname(path))
    File.write!(path, contents)
    path
  end

  describe "new-name candidates" do
    test "loads each candidate in order", %{root: root} do
      for name <-
            ~w(SIGILGUARD_POLICY .sigilguard-policy .sigilguard/policy .github/sigilguard-policy) do
        clean = Path.join(System.tmp_dir!(), "one-#{System.unique_integer([:positive])}")
        File.mkdir_p!(clean)
        write(clean, name, @policy)
        assert {:ok, %PolicyFile{rules: [_]}} = PolicyFile.load(clean), name
        File.rm_rf!(clean)
      end

      _ = root
    end

    test "returns :not_found when no candidate exists", %{root: root} do
      assert PolicyFile.load(root) == {:error, :not_found}
    end

    test "propagates a parse error from the loaded file", %{root: root} do
      write(root, "SIGILGUARD_POLICY", "no version line here\n")
      assert PolicyFile.load(root) == {:error, :invalid_policy_file}
    end
  end

  describe "legacy filenames fail closed" do
    @legacy [
      {"SIGIL_POLICY", "SIGILGUARD_POLICY"},
      {".sigil-policy", ".sigilguard-policy"},
      {".sigil/policy", ".sigilguard/policy"},
      {".github/sigil-policy", ".github/sigilguard-policy"}
    ]

    test "each legacy name fails with its 1:1 replacement", %{root: root} do
      for {legacy, replacement} <- @legacy do
        clean = Path.join(System.tmp_dir!(), "legacy-#{System.unique_integer([:positive])}")
        File.mkdir_p!(clean)
        found = write(clean, legacy, "anything")

        assert PolicyFile.load(clean) ==
                 {:error, {:legacy_policy_filename, found, replacement}}

        File.rm_rf!(clean)
      end

      _ = root
    end

    test "a legacy file wins even when a new-name file also exists", %{root: root} do
      write(root, "SIGILGUARD_POLICY", @policy)
      found = write(root, "SIGIL_POLICY", "anything")

      assert PolicyFile.load(root) ==
               {:error, {:legacy_policy_filename, found, "SIGILGUARD_POLICY"}}
    end
  end

  describe "path safety" do
    test "candidates resolving outside the repo root are ignored", %{root: root} do
      assert PolicyFile.load(root, candidates: ["../escape", "/etc/passwd"]) ==
               {:error, :not_found}
    end

    test "oversized files fail :policy_too_large", %{root: root} do
      write(root, "SIGILGUARD_POLICY", "version 3\n" <> String.duplicate("x", 256 * 1024))
      assert PolicyFile.load(root) == {:error, :policy_too_large}
    end
  end
end
