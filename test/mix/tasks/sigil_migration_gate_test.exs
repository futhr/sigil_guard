defmodule Mix.Tasks.Sigil.MigrationGateTest do
  @moduledoc false

  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Mix.Tasks.Sigil.MigrationGate

  describe "run/1" do
    test "prints success for the repository migration guide" do
      output =
        capture_io(fn ->
          assert :ok = MigrationGate.run([])
        end)

      assert output =~ "Migration gate passed"
    end

    test "rejects command line arguments" do
      assert_raise Mix.Error, ~r/does not accept options/, fn ->
        MigrationGate.run(["--bad"])
      end
    end
  end

  describe "validate/1" do
    test "accepts present mappings and valid local anchors" do
      root =
        fixture_root(%{
          "MIGRATING-3.0.md" => """
          # Migrating

          See [Registry](#registry-to-trust-bundles).

          ## Registry To Trust Bundles

          `SigilGuard.Registry.fetch_bundle/1`
          """
        })

      assert :ok =
               MigrationGate.validate(
                 root: root,
                 required_mappings: [function: "SigilGuard.Registry.fetch_bundle/1"]
               )
    end

    test "reports missing required mappings" do
      root = fixture_root(%{"MIGRATING-3.0.md" => "# Migrating\n"})

      assert {:error, [finding]} =
               MigrationGate.validate(
                 root: root,
                 required_mappings: [module: "SigilGuard.Envelope"]
               )

      assert finding.check == :missing_mapping
      assert finding.message == "module SigilGuard.Envelope is not mapped"
    end

    test "reports broken local anchors" do
      root =
        fixture_root(%{
          "MIGRATING-3.0.md" => """
          # Migrating

          See [Missing](#missing-section).
          """
        })

      assert {:error, [finding]} = MigrationGate.validate(root: root, required_mappings: [])
      assert finding.check == :invalid_link
      assert finding.message == "missing anchor: #missing-section"
    end
  end

  defp fixture_root(files) do
    root =
      Path.join(System.tmp_dir!(), "sigil_migration_gate_#{System.unique_integer([:positive])}")

    File.rm_rf!(root)

    Enum.each(files, fn {relative_path, content} ->
      path = Path.join(root, relative_path)
      File.mkdir_p!(Path.dirname(path))
      File.write!(path, content)
    end)

    root
  end
end
