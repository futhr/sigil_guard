defmodule SigilGuard.ApplicationTest do
  @moduledoc false

  use ExUnit.Case, async: false

  test "application supervisor is running under the OTP application" do
    assert Process.whereis(SigilGuard.Supervisor)

    assert Enum.any?(Application.started_applications(), fn {app, _, _} ->
             app == :sigil_guard
           end)
  end

  test "boot-owned ETS tables are available" do
    assert :ets.whereis(:sigil_guard_rates) != :undefined
    assert :ets.whereis(:sigil_guard_replay) != :undefined
    assert :ets.whereis(:sigil_guard_trust_bundle) != :undefined
    assert :ets.whereis(:sigil_guard_trust_bundle_quarantine) != :undefined
  end
end
