defmodule SigilGuard.VerdictTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Verdict

  test "verdicts/0 lists the five verdicts weakest to strongest" do
    assert Verdict.verdicts() == [:allow, :redact, :confirm, :quarantine, :block]
  end

  test "verdict?/1 recognizes only the closed set" do
    for v <- Verdict.verdicts(), do: assert(Verdict.verdict?(v))
    refute Verdict.verdict?(:allowed)
    refute Verdict.verdict?(:require_approval)
  end

  test "the total order is allow < redact < confirm < quarantine < block" do
    ranks = Enum.map(Verdict.verdicts(), &Verdict.rank/1)
    assert ranks == [0, 1, 2, 3, 4]
    assert ranks == Enum.sort(ranks)
    assert ranks == Enum.uniq(ranks)
  end

  test "compare/2 follows the strictness order" do
    assert Verdict.compare(:allow, :block) == :lt
    assert Verdict.compare(:block, :redact) == :gt
    assert Verdict.compare(:confirm, :confirm) == :eq
  end

  test "strongest/2 returns the stricter verdict" do
    assert Verdict.strongest(:allow, :redact) == :redact
    assert Verdict.strongest(:block, :quarantine) == :block
    assert Verdict.strongest(:confirm, :confirm) == :confirm
  end

  test "strongest/1 over a list defaults to allow when empty" do
    assert Verdict.strongest([]) == :allow
    assert Verdict.strongest([:allow, :confirm, :redact]) == :confirm
    assert Verdict.strongest([:redact, :quarantine, :block, :confirm]) == :block
  end
end
