defmodule SigilGuard.ConfigErrorTest do
  @moduledoc false

  use ExUnit.Case, async: true

  test "builds migration-oriented configuration errors" do
    error = SigilGuard.ConfigError.new(:registry_url, :legacy_contract_removed, "removed")

    assert error.key == :registry_url
    assert error.reason == :legacy_contract_removed
    assert error.message =~ ":registry_url"
    assert error.message =~ "legacy_contract_removed"
    assert error.message =~ "MIGRATING-1.0.md"
  end
end
