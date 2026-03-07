defmodule SigilGuard.AuditTest do
  @moduledoc """
  Tests for `SigilGuard.Audit`.

  Covers audit event creation, HMAC chain building, chain verification,
  and tamper detection across chains of varying lengths.
  """

  use ExUnit.Case, async: true

  alias SigilGuard.Audit

  @secret_key :crypto.strong_rand_bytes(32)

  describe "new_event/5" do
    test "creates an unsigned event with all required fields" do
      event = Audit.new_event("mcp.tool_call", "did:web:alice", "read_file", "success")

      assert event.type == "mcp.tool_call"
      assert event.actor == "did:web:alice"
      assert event.action == "read_file"
      assert event.result == "success"
      assert is_binary(event.id)
      assert is_binary(event.timestamp)
      assert event.metadata == %{}
      assert event.hmac == nil
      assert event.prev_hmac == nil
    end

    test "accepts metadata" do
      event =
        Audit.new_event("test", "actor", "action", "result", %{tool: "read_file", args: %{}})

      assert event.metadata == %{tool: "read_file", args: %{}}
    end

    test "generates unique IDs" do
      events = for _ <- 1..100, do: Audit.new_event("test", "actor", "action", "result")
      ids = Enum.map(events, & &1.id)

      assert length(Enum.uniq(ids)) == 100
    end
  end

  describe "sign_event/3" do
    test "signs the first event in a chain (genesis)" do
      event = Audit.new_event("test", "actor", "action", "success")
      signed = Audit.sign_event(event, @secret_key)

      assert is_binary(signed.hmac)
      assert byte_size(signed.hmac) == 64
      assert signed.prev_hmac == nil
    end

    test "signs a subsequent event with chain link" do
      first = Audit.new_event("test", "actor", "action1", "ok")
      first_signed = Audit.sign_event(first, @secret_key)

      second = Audit.new_event("test", "actor", "action2", "ok")
      second_signed = Audit.sign_event(second, @secret_key, first_signed.hmac)

      assert second_signed.prev_hmac == first_signed.hmac
      assert second_signed.hmac != first_signed.hmac
    end

    test "same event with different keys produces different HMACs" do
      event = Audit.new_event("test", "actor", "action", "ok")
      key1 = :crypto.strong_rand_bytes(32)
      key2 = :crypto.strong_rand_bytes(32)

      signed1 = Audit.sign_event(event, key1)
      signed2 = Audit.sign_event(event, key2)

      assert signed1.hmac != signed2.hmac
    end
  end

  describe "verify_chain/2" do
    test "verifies a valid chain of events" do
      events = [
        Audit.new_event("test", "alice", "action1", "ok"),
        Audit.new_event("test", "alice", "action2", "ok"),
        Audit.new_event("test", "alice", "action3", "ok")
      ]

      signed = Audit.build_chain(events, @secret_key)

      assert :ok = Audit.verify_chain(signed, @secret_key)
    end

    test "detects tampering in the middle of a chain" do
      events = [
        Audit.new_event("test", "alice", "action1", "ok"),
        Audit.new_event("test", "alice", "action2", "ok"),
        Audit.new_event("test", "alice", "action3", "ok")
      ]

      signed = Audit.build_chain(events, @secret_key)

      # Tamper with the second event
      tampered = List.update_at(signed, 1, fn event -> %{event | action: "tampered"} end)

      assert {:broken, 1} = Audit.verify_chain(tampered, @secret_key)
    end

    test "detects tampering of the first event" do
      events = [
        Audit.new_event("test", "alice", "action1", "ok"),
        Audit.new_event("test", "alice", "action2", "ok")
      ]

      signed = Audit.build_chain(events, @secret_key)
      tampered = List.update_at(signed, 0, fn event -> %{event | actor: "evil"} end)

      assert {:broken, 0} = Audit.verify_chain(tampered, @secret_key)
    end

    test "detects broken chain links when prev_hmac is corrupted" do
      events = [
        Audit.new_event("test", "alice", "action1", "ok"),
        Audit.new_event("test", "alice", "action2", "ok"),
        Audit.new_event("test", "alice", "action3", "ok")
      ]

      signed = Audit.build_chain(events, @secret_key)

      # Corrupt the prev_hmac of the second event to break the chain
      broken =
        List.update_at(signed, 1, fn event ->
          %{event | prev_hmac: "corrupted_hmac_value"}
        end)

      assert {:broken, 1} = Audit.verify_chain(broken, @secret_key)
    end

    test "detects wrong key" do
      events = [Audit.new_event("test", "alice", "action", "ok")]
      signed = Audit.build_chain(events, @secret_key)

      wrong_key = :crypto.strong_rand_bytes(32)
      assert {:broken, 0} = Audit.verify_chain(signed, wrong_key)
    end

    test "verifies a single-event chain" do
      events = [Audit.new_event("test", "alice", "action", "ok")]
      signed = Audit.build_chain(events, @secret_key)

      assert :ok = Audit.verify_chain(signed, @secret_key)
    end

    test "empty chain is valid" do
      assert :ok = Audit.verify_chain([], @secret_key)
    end
  end

  describe "build_chain/2" do
    test "signs events in sequence with chain links" do
      events = [
        Audit.new_event("test", "alice", "a1", "ok"),
        Audit.new_event("test", "alice", "a2", "ok"),
        Audit.new_event("test", "alice", "a3", "ok")
      ]

      signed = Audit.build_chain(events, @secret_key)

      assert length(signed) == 3

      # First event has no prev_hmac
      assert Enum.at(signed, 0).prev_hmac == nil

      # Second event links to first
      assert Enum.at(signed, 1).prev_hmac == Enum.at(signed, 0).hmac

      # Third event links to second
      assert Enum.at(signed, 2).prev_hmac == Enum.at(signed, 1).hmac
    end
  end

  describe "typed audit fields" do
    test "new events have nil typed fields by default" do
      event = Audit.new_event("test", "actor", "action", "result")

      assert event.event_type == nil
      assert event.actor_info == nil
      assert event.action_info == nil
      assert event.result_info == nil
    end

    test "accepts typed Actor struct" do
      actor = %SigilGuard.Audit.Actor{
        channel: "mcp",
        user_id: "did:web:alice",
        username: "Alice"
      }

      event = %{Audit.new_event("test", "actor", "action", "result") | actor_info: actor}
      assert event.actor_info.channel == "mcp"
      assert event.actor_info.user_id == "did:web:alice"
    end

    test "accepts typed Action struct" do
      action = %SigilGuard.Audit.Action{
        description: "read_file",
        risk_level: :low,
        approved: true,
        allowed: true
      }

      event = %{Audit.new_event("test", "actor", "action", "result") | action_info: action}
      assert event.action_info.risk_level == :low
    end

    test "accepts typed ExecutionResult struct" do
      result = %SigilGuard.Audit.ExecutionResult{
        success: true,
        exit_code: 0,
        duration_ms: 42,
        error: nil
      }

      event = %{Audit.new_event("test", "actor", "action", "result") | result_info: result}
      assert event.result_info.success == true
      assert event.result_info.duration_ms == 42
    end
  end

  describe "secure_compare edge cases" do
    test "detects tampered HMAC with different length" do
      events = [Audit.new_event("test", "alice", "action", "ok")]
      signed = Audit.build_chain(events, @secret_key)

      # Replace HMAC with a shorter string to trigger different-length branch
      short_hmac = List.update_at(signed, 0, fn e -> %{e | hmac: "short"} end)
      assert {:broken, 0} = Audit.verify_chain(short_hmac, @secret_key)
    end
  end

  describe "canonical_bytes/1" do
    test "produces deterministic JSON" do
      event = %Audit{
        id: "abc123",
        type: "mcp.tool_call",
        actor: "did:web:alice",
        action: "read_file",
        result: "success",
        timestamp: "2024-01-01T00:00:00.000Z"
      }

      bytes = Audit.canonical_bytes(event)

      # Keys should be in alphabetical order
      assert bytes ==
               ~s({"action":"read_file","actor":"did:web:alice","id":"abc123","result":"success","timestamp":"2024-01-01T00:00:00.000Z","type":"mcp.tool_call"})
    end

    test "excludes hmac, prev_hmac, and metadata" do
      event = %Audit{
        id: "x",
        type: "t",
        actor: "a",
        action: "act",
        result: "r",
        timestamp: "ts",
        hmac: "should_not_appear",
        prev_hmac: "also_excluded",
        metadata: %{secret: "hidden"}
      }

      bytes = Audit.canonical_bytes(event)
      decoded = Jason.decode!(bytes)

      refute Map.has_key?(decoded, "hmac")
      refute Map.has_key?(decoded, "prev_hmac")
      refute Map.has_key?(decoded, "metadata")
    end
  end
end
