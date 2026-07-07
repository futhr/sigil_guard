defmodule SigilGuard.Audit.ExecutionResultTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Audit.ExecutionResult

  test "captures execution result fields with nil defaults" do
    assert %ExecutionResult{} = result = %ExecutionResult{}
    assert result.success == nil
    assert result.exit_code == nil
    assert result.duration_ms == nil
    assert result.error == nil
  end

  test "stores execution facts without coercion" do
    result = %ExecutionResult{success: false, exit_code: 1, duration_ms: 42, error: "failed"}

    refute result.success
    assert result.exit_code == 1
    assert result.duration_ms == 42
    assert result.error == "failed"
  end
end
