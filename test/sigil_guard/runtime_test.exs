defmodule SigilGuard.RuntimeTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Runtime

  @tables [
    :sigil_guard_rates,
    :sigil_guard_replay,
    :sigil_guard_trust_bundle,
    :sigil_guard_trust_bundle_quarantine
  ]

  test "the Hex application automatically starts the singleton security runtime" do
    assert Application.spec(:sigil_guard, :mod) == {SigilGuard.Application, []}
    assert Process.whereis(Runtime)
  end

  test "runtime owns the ETS tables and validated configuration" do
    runtime = Process.whereis(Runtime)

    assert Keyword.fetch!(Runtime.configuration(runtime), :trust_bundle) == :none
    assert Keyword.fetch!(Runtime.configuration(runtime), :runtime)

    for table <- @tables do
      assert :ets.info(table, :owner) == runtime
    end
  end
end
