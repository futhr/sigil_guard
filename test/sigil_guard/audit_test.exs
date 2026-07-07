defmodule SigilGuard.AuditTest do
  @moduledoc false

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias SigilGuard.Audit
  alias SigilGuard.Audit.Checkpoint

  @secret_key :crypto.strong_rand_bytes(32)
  @field_hash_key :crypto.hash(:sha256, "audit field hash test key")
  @query_key :crypto.hash(:sha256, "audit query test key")

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

    test "rejects malformed previous HMAC anchors" do
      event = Audit.new_event("test", "actor", "action", "ok")
      Process.put(:sigil_guard_bad_prev_hmac, false)

      assert_raise ArgumentError, ~r/prev_hmac must be a binary or nil/, fn ->
        Audit.sign_event(event, @secret_key, Process.get(:sigil_guard_bad_prev_hmac))
      end
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

    test "detects deletion of the first event" do
      events = build_signed_chain(3)

      assert {:broken, 0} = Audit.verify_chain(tl(events), @secret_key)
    end

    test "detects deletion of a middle event" do
      events = build_signed_chain(3)

      assert {:broken, 1} = Audit.verify_chain(List.delete_at(events, 1), @secret_key)
    end

    test "detects reordered events" do
      [first, second, third] = build_signed_chain(3)

      assert {:broken, 1} = Audit.verify_chain([first, third, second], @secret_key)
    end

    test "detects a forged self-consistent first event" do
      # An event whose hmac correctly covers a fabricated prev_hmac used
      # to verify as a chain head; the genesis link must be enforced.
      fake_prev = Base.encode16(:crypto.strong_rand_bytes(32), case: :lower)

      forged =
        Audit.new_event("test", "mallory", "action", "ok")
        |> Audit.sign_event(@secret_key, fake_prev)

      assert {:broken, 0} = Audit.verify_chain([forged], @secret_key)
    end

    test "detects an unsigned event in the chain" do
      [first, second] = build_signed_chain(2)
      unsigned = %{second | hmac: nil}

      assert {:broken, 1} = Audit.verify_chain([first, unsigned], @secret_key)
    end
  end

  describe "verify_chain/3 with :prev_hmac anchor" do
    test "verifies a continuation segment against a stored tip" do
      [first, second, third] = build_signed_chain(3)

      assert :ok = Audit.verify_chain([second, third], @secret_key, prev_hmac: first.hmac)
    end

    test "rejects a segment anchored to the wrong tip" do
      [_, second, third] = build_signed_chain(3)
      wrong_tip = Base.encode16(:crypto.strong_rand_bytes(32), case: :lower)

      assert {:broken, 0} =
               Audit.verify_chain([second, third], @secret_key, prev_hmac: wrong_tip)
    end

    test "nil anchor behaves like genesis verification" do
      signed = build_signed_chain(2)

      assert :ok = Audit.verify_chain(signed, @secret_key, prev_hmac: nil)
    end

    test "rejects malformed continuation anchors instead of treating them as genesis" do
      signed = build_signed_chain(1)

      assert {:broken, 0} = Audit.verify_chain(signed, @secret_key, prev_hmac: false)
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
      assert Enum.at(signed, 0).prev_hmac == nil
      assert Enum.at(signed, 1).prev_hmac == Enum.at(signed, 0).hmac
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

  describe "hash_field/2 (SP.05 privacy)" do
    test "returns the fh1: HMAC form for a value and key" do
      hashed = Audit.hash_field("did:web:alice", @field_hash_key)

      assert String.starts_with?(hashed, "fh1:")
      assert byte_size(hashed) == byte_size("fh1:") + 64
      # Deterministic and key-bound.
      assert Audit.hash_field("did:web:alice", @field_hash_key) == hashed
      refute Audit.hash_field("did:web:bob", @field_hash_key) == hashed
      refute Audit.hash_field("did:web:alice", :crypto.hash(:sha256, "other")) == hashed
    end

    test "fails closed to redacted-v1 without a usable key" do
      assert Audit.hash_field("did:web:alice", nil) == "redacted-v1"
      assert Audit.hash_field("did:web:alice", "") == "redacted-v1"
      assert Audit.hash_field(123, @field_hash_key) == "redacted-v1"
    end
  end

  describe "classify/2 (SP.05 privacy)" do
    setup do
      event = %Audit{
        id: "00000000000000000000000000000001",
        type: "runtime.gate",
        actor: "did:web:alice",
        action: "repo_file_write",
        result: "block",
        timestamp: "2026-07-02T12:00:00.000Z",
        metadata: %{"decision_id" => "abc"}
      }

      %{event: event}
    end

    test "hashes the actor and leaves the clear fields and metadata untouched", ctx do
      classified = Audit.classify(ctx.event, field_hash_key: @field_hash_key)

      assert classified.actor == Audit.hash_field("did:web:alice", @field_hash_key)
      assert classified.id == ctx.event.id
      assert classified.type == ctx.event.type
      assert classified.action == ctx.event.action
      assert classified.result == ctx.event.result
      assert classified.timestamp == ctx.event.timestamp
      assert classified.metadata == ctx.event.metadata
    end

    test "fails closed when no field-hash key is supplied", ctx do
      assert Audit.classify(ctx.event).actor == "redacted-v1"
    end

    test "fails closed when the field-hash key reuses the chain key", ctx do
      classified = Audit.classify(ctx.event, field_hash_key: @secret_key, chain_key: @secret_key)
      assert classified.actor == "redacted-v1"
    end

    test "is idempotent on an already-classified actor", ctx do
      once = Audit.classify(ctx.event, field_hash_key: @field_hash_key)
      twice = Audit.classify(once, field_hash_key: @field_hash_key)
      assert twice.actor == once.actor

      redacted = Audit.classify(ctx.event)
      assert Audit.classify(redacted, field_hash_key: @field_hash_key).actor == "redacted-v1"
    end

    test "crypto-erasure of the field-hash key leaves chain verification green", ctx do
      classified = Audit.classify(ctx.event, field_hash_key: @field_hash_key)
      signed = Audit.sign_event(classified, @secret_key)

      # Verification uses only the chain key; the field-hash key is never needed.
      assert Audit.verify_chain([signed], @secret_key) == :ok
      refute Audit.canonical_bytes(signed) =~ "did:web:alice"
    end

    test "tampering with the hashed actor breaks the chain" do
      signed =
        %Audit{
          id: "id",
          type: "t",
          actor: "did:web:alice",
          action: "a",
          result: "ok",
          timestamp: "2026-07-02T12:00:00.000Z"
        }
        |> Audit.classify(field_hash_key: @field_hash_key)
        |> Audit.sign_event(@secret_key)

      tampered = %{signed | actor: Audit.hash_field("did:web:mallory", @field_hash_key)}
      assert Audit.verify_chain([tampered], @secret_key) == {:broken, 0}
    end

    property "no raw actor value survives in the signed canonical bytes" do
      # A distinctive prefix that cannot occur inside a lowercase-hex hash or the
      # short clear fields, so the substring check reflects a real leak only.
      check all(suffix <- string(:alphanumeric), max_runs: 200) do
        actor = "raw-actor:" <> suffix

        classified =
          %Audit{
            id: "id",
            type: "t",
            actor: actor,
            action: "a",
            result: "ok",
            timestamp: "2026-07-02T12:00:00.000Z"
          }
          |> Audit.classify(field_hash_key: @field_hash_key)
          |> Audit.sign_event(@secret_key)

        canonical = Audit.canonical_bytes(classified)

        assert String.starts_with?(classified.actor, "fh1:")
        refute String.contains?(canonical, actor)
      end
    end
  end

  describe "tip/1 (SP.05)" do
    test "returns the last event's coordinates" do
      events = query_events()
      last = List.last(events)

      assert Audit.tip(events) ==
               {:ok, %{index: 4, event_id: last.id, hmac: last.hmac, timestamp: last.timestamp}}
    end

    test "fails :empty_chain on an empty list and :unsigned_event on an unsigned tail" do
      assert Audit.tip([]) == {:error, :empty_chain}

      unsigned = Audit.new_event("test", "alice", "act", "ok")
      assert Audit.tip([unsigned]) == {:error, :unsigned_event}
      assert Audit.tip(Enum.concat(query_events(), [unsigned])) == {:error, :unsigned_event}
    end
  end

  describe "query/2 (SP.05)" do
    test "filters by type, id, and index range, preserving chain order" do
      events = query_events()

      assert {:ok, gate} = Audit.query(events, type: "gate")
      assert Enum.map(gate, & &1.id) == ["id0", "id2", "id4"]

      assert {:ok, [one]} = Audit.query(events, id: "id2")
      assert one.id == "id2"

      assert {:ok, span} = Audit.query(events, from_index: 1, to_index: 3)
      assert Enum.map(span, & &1.id) == ["id1", "id2", "id3"]
    end

    test "filters by an inclusive time window" do
      events = query_events()

      assert {:ok, window} =
               Audit.query(events,
                 from_time: "2026-07-02T12:00:02.000Z",
                 to_time: "2026-07-02T12:00:03.000Z"
               )

      assert Enum.map(window, & &1.id) == ["id2", "id3"]
    end

    test "composes filters with AND and returns {:ok, []} for no match" do
      events = query_events()

      assert {:ok, both} = Audit.query(events, type: "gate", from_index: 2)
      assert Enum.map(both, & &1.id) == ["id2", "id4"]

      assert Audit.query(events, id: "missing") == {:ok, []}
      assert Audit.query(events, []) == {:ok, events}
    end

    test "an unknown key or malformed option value fails :invalid_query" do
      events = query_events()

      assert Audit.query(events, bogus: 1) == {:error, :invalid_query}
      assert Audit.query(events, from_time: "not-a-date") == {:error, :invalid_query}
      assert Audit.query(events, from_time: 123) == {:error, :invalid_query}
      assert Audit.query(events, from_index: "0") == {:error, :invalid_query}
      assert Audit.query(events, to_index: "x") == {:error, :invalid_query}
      assert Audit.query("not a list", []) == {:error, :invalid_query}
    end

    test "excludes events with an unparsable timestamp from a time window" do
      undated = %{query_event(0) | timestamp: "not-a-date"}
      events = Audit.build_chain([undated], @query_key)
      assert Audit.query(events, from_time: "2026-07-02T12:00:00.000Z") == {:ok, []}
    end

    test "an out-of-range index fails :out_of_range" do
      events = query_events()

      assert Audit.query(events, from_index: 5) == {:error, :out_of_range}
      assert Audit.query(events, to_index: 5) == {:error, :out_of_range}
      assert Audit.query(events, from_index: 3, to_index: 1) == {:error, :out_of_range}
    end
  end

  describe "checkpoint_boundaries/2 (SP.05)" do
    test "locates each checkpoint's event span" do
      events = query_events()

      {:ok, checkpoint} =
        Checkpoint.create(Enum.take(events, 3), generated_at: "2026-07-02T12:00:03.000Z")

      assert {:ok, [boundary]} = Audit.checkpoint_boundaries(events, [checkpoint])

      assert boundary == %{
               checkpoint_digest: Checkpoint.digest(checkpoint),
               tree_size: 3,
               first_index: 0,
               last_index: 2
             }
    end

    test "a span that disagrees with event_count fails :checkpoint_mismatch" do
      events = query_events()

      {:ok, checkpoint} =
        Checkpoint.create(Enum.take(events, 3), generated_at: "2026-07-02T12:00:03.000Z")

      inflated = Map.put(checkpoint, "event_count", 99)

      assert Audit.checkpoint_boundaries(events, [inflated]) == {:error, :checkpoint_mismatch}
    end

    test "an empty checkpoint yields nil indices" do
      events = query_events()
      {:ok, empty} = Checkpoint.create([], generated_at: "2026-07-02T12:00:00.000Z")

      assert {:ok, [%{tree_size: 0, first_index: nil, last_index: nil}]} =
               Audit.checkpoint_boundaries(events, [empty])
    end

    test "a non-checkpoint term or non-list input fails :invalid_query" do
      assert Audit.checkpoint_boundaries(query_events(), ["nope"]) == {:error, :invalid_query}
      assert Audit.checkpoint_boundaries(query_events(), [%{}]) == {:error, :invalid_query}
      assert Audit.checkpoint_boundaries("not a list", []) == {:error, :invalid_query}
    end
  end

  describe "read purity (SP.05)" do
    test "tip/query/checkpoint_boundaries emit no telemetry" do
      # A unique actor so the handler ignores audit events from concurrent tests;
      # the events are signed before the handler attaches, so only a read that
      # (wrongly) emits could reach it.
      actor = "purity-actor-#{System.unique_integer()}"

      events =
        Enum.map(0..2, fn i ->
          %Audit{
            id: "p#{i}",
            type: "gate",
            actor: actor,
            action: "a",
            result: "ok",
            timestamp: "2026-07-02T12:00:0#{i}.000Z"
          }
        end)
        |> Audit.build_chain(@query_key)

      {:ok, checkpoint} = Checkpoint.create(events, generated_at: "2026-07-02T12:00:05.000Z")

      parent = self()
      handler_id = "audit-read-purity-#{System.unique_integer()}"

      :telemetry.attach_many(
        handler_id,
        [[:sigil_guard, :audit, :logged]],
        fn event, _, metadata, _ ->
          if metadata[:actor] == actor, do: send(parent, {:emitted, event})
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      assert {:ok, _} = Audit.tip(events)
      assert {:ok, _} = Audit.query(events, type: "gate")
      assert {:ok, _} = Audit.checkpoint_boundaries(events, [checkpoint])

      refute_receive {:emitted, _}, 50
    end
  end

  # A five-event signed chain with fixed ids/types/timestamps for query tests.
  defp query_events do
    0..4
    |> Enum.map(&query_event/1)
    |> Audit.build_chain(@query_key)
  end

  defp query_event(i) do
    %Audit{
      id: "id#{i}",
      type: if(rem(i, 2) == 0, do: "gate", else: "mcp"),
      actor: "alice",
      action: "act#{i}",
      result: "ok",
      timestamp: "2026-07-02T12:00:0#{i}.000Z"
    }
  end

  defp build_signed_chain(count) do
    1..count
    |> Enum.map(&Audit.new_event("test", "alice", "action#{&1}", "ok"))
    |> Audit.build_chain(@secret_key)
  end
end
