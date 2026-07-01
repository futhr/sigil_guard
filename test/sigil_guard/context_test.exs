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

    test "ignores unknown string keys without atomizing them" do
      context = Context.new(%{"unknown-key" => "value", "phase" => :tool_result})

      assert context.phase == :tool_result
      refute Map.has_key?(Map.from_struct(context), :"unknown-key")
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
  end

  describe "action_name/2" do
    test "prefers explicit context action" do
      context = Context.new(action: "send_email", tool: "mail")

      assert Context.action_name(context, %{}) == "send_email"
    end

    test "falls back to tool payload" do
      assert Context.action_name(Context.new(%{}), %{"tool" => "read_file"}) == "read_file"
    end
  end
end
