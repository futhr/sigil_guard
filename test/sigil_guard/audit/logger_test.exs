defmodule SigilGuard.Audit.LoggerTest do
  @moduledoc false

  use ExUnit.Case, async: true

  defmodule TestLogger do
    @behaviour SigilGuard.Audit.Logger

    @impl SigilGuard.Audit.Logger
    def log(event) do
      send(event.test_pid, {:logged, event})
      :ok
    end
  end

  defmodule FailingLogger do
    @behaviour SigilGuard.Audit.Logger

    @impl SigilGuard.Audit.Logger
    def log(_), do: {:error, :disk_full}
  end

  test "defines the audit persistence callback contract" do
    event = %{test_pid: self(), action: "scan"}

    assert TestLogger.log(event) == :ok
    assert_receive {:logged, ^event}
  end

  test "allows logger backends to return typed errors" do
    assert FailingLogger.log(%{}) == {:error, :disk_full}
  end

  test "exports the required behaviour callback" do
    assert {:log, 1} in SigilGuard.Audit.Logger.behaviour_info(:callbacks)
  end
end
