Code.require_file("../../bin/mutation_report.exs", __DIR__)

defmodule SigilGuard.MutationReportTest do
  use ExUnit.Case, async: true
  alias SigilGuard.MutationReport

  test "empty, unknown and timeout results cannot count as killed" do
    source = File.read!("lib/sigil_guard/verdict.ex")

    for status <- ["survived", "timeout", "unknown", "invalid"] do
      report = %{"mutations" => [%{"status" => "killed"}, %{"status" => status}]}
      assert {:error, _} = MutationReport.validate(report, source)
    end

    assert {:error, _} = MutationReport.validate(%{"mutations" => []}, source)

    startup = %{"status" => "invalid", "error" => "{:compile_error, Could not start application}"}

    compiler = %{
      "status" => "invalid",
      "error" => "{:compile_error, == Compilation error in file}"
    }

    assert {:error, _} =
             MutationReport.validate(%{"mutations" => [%{"status" => "killed"}, startup]}, source)

    assert {:ok, %{invalid: 1}} =
             MutationReport.validate(
               %{"mutations" => [%{"status" => "killed"}, compiler]},
               source
             )
  end

  test "equivalence requires both the exact source and proved fragment" do
    source = File.read!("lib/sigil_guard/verdict.ex")

    mutation = %{
      "status" => "survived",
      "patch" => %{"before" => "strongest(a, b)", "after" => "strongest(b, a)"},
      "location" => %{"file" => "lib/sigil_guard/verdict.ex"}
    }

    report = %{"mutations" => [%{"status" => "killed"}, mutation]}
    assert {:ok, %{equivalent: 1, killed: 1}} = MutationReport.validate(report, source)
    assert {:error, _} = MutationReport.validate(report, source <> "\n")
  end
end
