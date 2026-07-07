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
    now = System.system_time(:millisecond)

    :ets.insert(@table, {{"expired", "first"}, now - 1})
    assert ReplayStore.check_and_put("identity", "first", 60_000) == :ok
    assert :ets.lookup(@table, {"expired", "first"}) == []

    :ets.insert(@table, {{"expired", "second"}, now - 1})
    assert ReplayStore.check_and_put("identity", "second", 60_000) == :ok
    assert [{_, expires_at}] = :ets.lookup(@table, {"expired", "second"})
    assert expires_at < now
  end
end
