defmodule SigilGuard.LifecycleTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Lifecycle

  @phases [
    :session_start,
    :tool_request,
    :permission_requested,
    :permission_resolved,
    :tool_result,
    :file_changed,
    :model_ingress,
    :model_egress,
    :session_end
  ]

  test "phases/0 returns the nine phases in canonical order" do
    assert Lifecycle.phases() == @phases
  end

  test "phase?/1 recognizes only taxonomy members" do
    for phase <- @phases, do: assert(Lifecycle.phase?(phase))
    refute Lifecycle.phase?(:inbound_user)
    refute Lifecycle.phase?("tool_request")
    refute Lifecycle.phase?(nil)
  end

  test "blockable?/1 marks session events notification-only and the rest blockable" do
    assert Lifecycle.blockable?(:tool_request)
    assert Lifecycle.blockable?(:model_egress)
    refute Lifecycle.blockable?(:session_start)
    refute Lifecycle.blockable?(:session_end)
    refute Lifecycle.blockable?(:not_a_phase)
  end

  test "notify_only?/1 is the complement of blockable? over the taxonomy" do
    for phase <- @phases do
      assert Lifecycle.notify_only?(phase) == not Lifecycle.blockable?(phase)
    end
  end

  describe "cast/1" do
    test "accepts atoms and strings for each phase" do
      for phase <- @phases do
        assert Lifecycle.cast(phase) == {:ok, phase}
        assert Lifecycle.cast(Atom.to_string(phase)) == {:ok, phase}
      end
    end

    test "rejects unknown phases without minting atoms" do
      assert Lifecycle.cast("unknown_phase") == :error
      assert Lifecycle.cast(:inbound_user) == :error
      assert Lifecycle.cast(42) == :error
    end
  end

  describe "from_context_phase/1" do
    test "maps the five legacy context phases" do
      assert Lifecycle.from_context_phase(:inbound_user) == {:ok, :model_ingress}
      assert Lifecycle.from_context_phase(:outbound_model) == {:ok, :model_egress}
      assert Lifecycle.from_context_phase(:repo_change) == {:ok, :file_changed}
      assert Lifecycle.from_context_phase(:tool_request) == {:ok, :tool_request}
      assert Lifecycle.from_context_phase(:tool_result) == {:ok, :tool_result}
    end

    test "rejects unknown context phases" do
      assert Lifecycle.from_context_phase(:session_start) == :error
      assert Lifecycle.from_context_phase("inbound_user") == :error
    end
  end
end
