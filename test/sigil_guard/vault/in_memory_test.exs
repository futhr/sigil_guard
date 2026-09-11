defmodule SigilGuard.Vault.InMemoryTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Vault.InMemory

  setup do
    key = :crypto.strong_rand_bytes(32)
    start_supervised!({InMemory, master_key: key})
    %{key: key}
  end

  test "invalid encryption preserves the vault process and all existing entries" do
    pid = Process.whereis(InMemory)
    {:ok, existing} = InMemory.encrypt("retained", "valid")

    for value <- [%{}, nil, ["iodata"], self()] do
      assert InMemory.encrypt(value, "description") == {:error, :invalid_plaintext}
      assert InMemory.encrypt("secret", value) == {:error, :invalid_description}
    end

    assert InMemory.encrypt("secret", <<255>>) == {:error, :invalid_description}
    assert Process.whereis(InMemory) == pid
    assert Process.alive?(pid)
    assert InMemory.decrypt(existing) == {:ok, "retained"}
    assert InMemory.list_entries() == [{existing, "valid"}]

    for plaintext <- ["", <<0, 255, 128>>] do
      assert {:ok, id} = InMemory.encrypt(plaintext, "")
      assert InMemory.decrypt(id) == {:ok, plaintext}
    end
  end

  test "encrypts, lists, decrypts, and deletes entries through the singleton process" do
    assert {:ok, id} = InMemory.encrypt("secret", "API key")
    assert InMemory.exists?(id)
    assert {id, "API key"} in InMemory.list_entries()
    assert {:ok, "secret"} = InMemory.decrypt(id)
    assert :ok = InMemory.delete(id)
    refute InMemory.exists?(id)
    assert {:error, :not_found} = InMemory.decrypt(id)
  end

  test "redacts the configured master key from process status", %{key: key} do
    {:status, _, _, items} = :sys.get_status(InMemory)
    status = inspect(items, limit: :infinity)

    assert status =~ "REDACTED"
    refute status =~ inspect(key)
  end

  test "rejects malformed master-key options before starting" do
    stop_supervised!(InMemory)
    Process.flag(:trap_exit, true)

    assert {:error, {:invalid_master_key, :invalid_length}} =
             InMemory.start_link(master_key: "short")

    assert {:error, :invalid_options} = InMemory.start_link(:bad)
  end
end
