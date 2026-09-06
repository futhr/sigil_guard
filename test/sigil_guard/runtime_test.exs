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

  test "runtime configuration resolves explicit built-in scanner options" do
    assert {:ok, []} = Runtime.scanner_options()
  end

  test "bundle pattern selection resolves explicitly and rejects an expired source" do
    alias SigilGuard.TrustBundle
    now = DateTime.utc_now(:millisecond)

    {:ok, bundle} =
      TrustBundle.dev_bundle(
        now: now,
        seed: :binary.copy(<<71>>, 32),
        patterns: [
          %{"name" => "custom", "set" => "secret", "regex" => "SPECIAL", "severity" => "high"}
        ]
      )

    previous = Runtime.configuration()

    config =
      SigilGuard.Config.validate!(
        scanner_patterns: :bundle,
        trust_bundle: {:map, bundle.envelope}
      )

    :sys.replace_state(Runtime, fn _ -> config end)
    on_exit(fn -> :sys.replace_state(Runtime, fn _ -> previous end) end)
    assert {:ok, opts} = Runtime.scanner_options(Runtime, now: now)
    assert {:hit, [%{name: "custom"}]} = SigilGuard.Scanner.scan("SPECIAL", opts)

    assert {:error, :bundle_expired} =
             Runtime.scanner_options(Runtime, now: DateTime.add(now, 2, :hour))
  end
end
