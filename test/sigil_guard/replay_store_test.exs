defmodule SigilGuard.ReplayStoreTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.ReplayStore

  @table :sigil_guard_replay

  setup do
    ReplayStore.clear()
    on_exit(&ReplayStore.clear/0)
    :ok
  end

  test "concurrent check_and_put allows exactly one claim for a nonce" do
    results =
      1..100
      |> Task.async_stream(
        fn _ -> ReplayStore.check_and_put("identity", "nonce", 60_000) end,
        max_concurrency: 100,
        timeout: 5_000
      )
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.count(results, &(&1 == :ok)) == 1
    assert Enum.count(results, &(&1 == {:error, :replay_detected})) == 99
  end

  test "expired nonce can be reclaimed" do
    assert ReplayStore.check_and_put("identity", "nonce", 1) == :ok
    Process.sleep(5)
    assert ReplayStore.check_and_put("identity", "nonce", 60_000) == :ok
    assert ReplayStore.check_and_put("identity", "nonce", 60_000) == {:error, :replay_detected}
  end

  test "pruning is amortized instead of full-table on every claim" do
    ReplayStore.ensure_table()
    now = System.monotonic_time(:millisecond)

    :ets.insert(@table, {{"expired", "first"}, now - 1})
    assert ReplayStore.check_and_put("identity", "first", 60_000) == :ok
    assert :ets.lookup(@table, {"expired", "first"}) == []

    :ets.insert(@table, {{"expired", "second"}, now - 1})
    assert ReplayStore.check_and_put("identity", "second", 60_000) == :ok
    assert [{_, expires_at}] = :ets.lookup(@table, {"expired", "second"})
    assert expires_at < now
  end

  test "capacity exhaustion fails closed without evicting a live nonce" do
    assert :ok = ReplayStore.check_and_put("identity", "one", 60_000, 1)

    assert {:error, :replay_capacity_exceeded} =
             ReplayStore.check_and_put("identity", "two", 60_000, 1)

    assert {:error, :replay_detected} = ReplayStore.check_and_put("identity", "one", 60_000, 1)
  end

  test "expiry is measured on the monotonic clock" do
    before = System.monotonic_time(:millisecond)
    assert :ok = ReplayStore.check_and_put("clock", "nonce", 60_000)
    assert [{{identity_hash, nonce_hash}, expiry}] = :ets.match_object(@table, {{:_, :_}, :_})
    assert byte_size(identity_hash) == 32
    assert byte_size(nonce_hash) == 32
    assert expiry >= before + 60_000
    assert expiry <= System.monotonic_time(:millisecond) + 60_000
  end

  test "attestation replay protection spans expiry skew despite a shorter override" do
    alias SigilGuard.Attestation
    alias SigilGuard.Attestation.Envelope
    now = ~U[2026-07-03 12:00:00.000Z]

    statement =
      SigilGuard.FixturePath.path("agent_trust/tool_request/statement.json")
      |> File.read!()
      |> Jason.decode!()

    statement =
      statement
      |> put_in(["predicate", "issued_at"], DateTime.to_iso8601(now))
      |> put_in(["predicate", "expires_at"], DateTime.to_iso8601(DateTime.add(now, 1, :second)))

    {:ok, envelope} = Attestation.sign(statement, SigilGuard.TestSigner)

    keys = %{
      Envelope.keyid(SigilGuard.TestSigner.public_key()) => SigilGuard.TestSigner.public_key()
    }

    opts = [now: DateTime.add(now, 2, :second), consume: true, replay_ttl_ms: 1]
    assert {:ok, _} = Attestation.verify(envelope, keys, opts)
    Process.sleep(5)
    assert {:error, :replay_detected} = Attestation.verify(envelope, keys, opts)
  end

  test "zero lifetimes and capacities are outside the public contract" do
    assert_raise FunctionClauseError, fn -> ReplayStore.check_and_put("identity", "nonce", 0) end

    assert_raise FunctionClauseError, fn ->
      ReplayStore.check_and_put("identity", "nonce", 1, 0)
    end
  end
end
