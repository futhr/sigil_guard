defmodule SigilGuard.Audit.ActionTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Audit.Action

  test "captures audit action fields with nil defaults" do
    assert %Action{} = action = %Action{}
    assert action.description == nil
    assert action.risk_level == nil
    assert action.approved == nil
    assert action.allowed == nil
  end

  test "stores policy action facts without coercion" do
    action = %Action{description: "read_file", risk_level: :low, approved: true, allowed: true}

    assert action.description == "read_file"
    assert action.risk_level == :low
    assert action.approved
    assert action.allowed
  end
end
