defmodule SigilGuard.ContextTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Context

  describe "new/1" do
    test "normalizes keyword context" do
      context = Context.new(phase: :tool_result, sink: :model, trust_level: :medium)

      assert context.phase == :tool_result
      assert context.sink == :model
      assert context.trust_level == :medium
      assert context.trust_zone == :semi_trusted
    end

    test "normalizes string-keyed context" do
      context = Context.new(%{"phase" => :repo_change, "sink" => :repo, "actor" => "codex"})

      assert context.phase == :repo_change
      assert context.sink == :repo
      assert context.actor == "codex"
    end

    test "normalizes JSON-style enum values" do
      context =
        Context.new(%{
          "phase" => "tool_result",
          "origin" => "tool",
          "sink" => "external",
          "trust_level" => "high",
          "trust_zone" => "untrusted",
          "intended_audience" => "model"
        })

      assert context.phase == :tool_result
      assert context.origin == :tool
      assert context.sink == :external
      assert context.trust_level == :high
      assert context.trust_zone == :untrusted
      assert context.intended_audience == :model
    end

    test "ignores unknown string keys without atomizing them" do
      context = Context.new(%{"unknown-key" => "value", "phase" => :tool_result})

      assert context.phase == :tool_result
      refute Map.has_key?(Map.from_struct(context), :"unknown-key")
    end
  end

  describe "validate/1" do
    test "accepts normalized context values" do
      assert :ok =
               Context.validate(%{
                 "phase" => "tool_result",
                 "sink" => "model",
                 "origin" => "tool",
                 "trust_level" => "high",
                 "trust_zone" => "trusted",
                 "intended_audience" => "internal"
               })
    end

    test "rejects malformed boundary labels" do
      assert {:error, :invalid_phase} = Context.validate(%{phase: "outside"})
      assert {:error, :invalid_sink} = Context.validate(%{sink: "outside"})
      assert {:error, :invalid_origin} = Context.validate(%{origin: "outside"})
      assert {:error, :invalid_trust_level} = Context.validate(%{trust_level: "admin"})
      assert {:error, :invalid_trust_zone} = Context.validate(%{trust_zone: "unknown"})
      assert {:error, :invalid_audience} = Context.validate(%{intended_audience: "unknown"})
      assert {:error, :invalid_metadata} = Context.validate(%{metadata: "bad"})
      assert {:error, :invalid_context} = Context.validate("bad")
    end
  end

  describe "text/1" do
    test "extracts common payload text fields" do
      assert Context.text(%{"content" => "hello"}) == "hello"
      assert Context.text(%{output: "result"}) == "result"
      assert Context.text("raw") == "raw"
    end

    test "returns nil for payloads without text" do
      assert Context.text(%{"content" => ["not", "a", "string"]}) == nil
      assert Context.text(123) == nil
    end

    test "does not let malformed primary text fields fall through to aliases" do
      payload = %{"text" => false, "content" => "safe fallback"}

      assert Context.text(payload) == nil
      assert Context.fetch_text(payload) == {:error, :invalid_text}
    end
  end

  describe "action_name/2" do
    test "prefers explicit context action" do
      context = Context.new(action: "send_email", tool: "mail")

      assert Context.action_name(context, %{}) == "send_email"
    end

    test "falls back to tool payload" do
      assert Context.action_name(Context.new(%{}), %{"tool" => "read_file"}) == "read_file"
    end

    test "does not let malformed action fields fall through to tool aliases" do
      context = Context.new(action: false, tool: "read_file")

      assert Context.action_name(context, %{"action" => "write_file"}) == "tool_call"

      assert Context.fetch_action_name(context, %{"action" => "write_file"}) ==
               {:error, :invalid_action}
    end

    test "does not let malformed payload action fields fall through to aliases" do
      payload = %{"action" => false, "tool" => "read_file"}

      assert Context.action_name(Context.new(%{}), payload) == "tool_call"
      assert Context.fetch_action_name(Context.new(%{}), payload) == {:error, :invalid_action}
    end
  end
end
