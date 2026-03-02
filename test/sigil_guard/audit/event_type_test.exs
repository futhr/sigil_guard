defmodule SigilGuard.Audit.EventTypeTest do
  @moduledoc """
  Tests for `SigilGuard.Audit.EventType`.

  Validates all 10 event type variants, string serialization/deserialization,
  and the validation function.
  """

  use ExUnit.Case, async: true

  alias SigilGuard.Audit.EventType

  @all_types [
    :command_execution,
    :file_access,
    :config_change,
    :auth_success,
    :auth_failure,
    :policy_violation,
    :security_event,
    :sigil_interception,
    :mcp_tool_gated,
    :delegation_crossing
  ]

  describe "values/0" do
    test "returns all 10 event types" do
      assert length(EventType.values()) == 10
      assert EventType.values() == @all_types
    end
  end

  describe "valid?/1" do
    test "returns true for all valid event types" do
      for type <- @all_types do
        assert EventType.valid?(type), "expected #{type} to be valid"
      end
    end

    test "returns false for invalid atoms" do
      refute EventType.valid?(:invalid)
      refute EventType.valid?(:unknown_event)
    end
  end

  describe "to_string/1" do
    test "converts all event types to PascalCase strings" do
      expected = [
        {:command_execution, "CommandExecution"},
        {:file_access, "FileAccess"},
        {:config_change, "ConfigChange"},
        {:auth_success, "AuthSuccess"},
        {:auth_failure, "AuthFailure"},
        {:policy_violation, "PolicyViolation"},
        {:security_event, "SecurityEvent"},
        {:sigil_interception, "SigilInterception"},
        {:mcp_tool_gated, "McpToolGated"},
        {:delegation_crossing, "DelegationCrossing"}
      ]

      for {atom, string} <- expected do
        assert EventType.to_string(atom) == string
      end
    end
  end

  describe "from_string/1" do
    test "parses all valid PascalCase strings" do
      expected = [
        {"CommandExecution", :command_execution},
        {"FileAccess", :file_access},
        {"ConfigChange", :config_change},
        {"AuthSuccess", :auth_success},
        {"AuthFailure", :auth_failure},
        {"PolicyViolation", :policy_violation},
        {"SecurityEvent", :security_event},
        {"SigilInterception", :sigil_interception},
        {"McpToolGated", :mcp_tool_gated},
        {"DelegationCrossing", :delegation_crossing}
      ]

      for {string, atom} <- expected do
        assert {:ok, ^atom} = EventType.from_string(string)
      end
    end

    test "returns :error for invalid strings" do
      assert :error = EventType.from_string("Invalid")
      assert :error = EventType.from_string("command_execution")
      assert :error = EventType.from_string("")
    end
  end

  describe "round-trip" do
    test "to_string and from_string are inverses" do
      for type <- @all_types do
        string = EventType.to_string(type)
        assert {:ok, ^type} = EventType.from_string(string)
      end
    end
  end
end
