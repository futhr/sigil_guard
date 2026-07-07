defmodule SigilGuard.Vault.EntryTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Vault.Entry

  test "uses safe defaults for optional vault entry fields" do
    entry = %Entry{}

    assert entry.id == nil
    assert entry.ciphertext == nil
    assert entry.description == nil
    assert entry.created_at == nil
    assert entry.tags == []
  end

  test "stores encrypted entry metadata without plaintext fields" do
    entry = %Entry{
      id: "vault_abc",
      ciphertext: <<1, 2, 3>>,
      description: "API key",
      created_at: "2026-01-01T00:00:00.000Z",
      tags: ["prod"]
    }

    assert entry.id == "vault_abc"
    assert entry.ciphertext == <<1, 2, 3>>
    assert entry.tags == ["prod"]
    refute Map.has_key?(Map.from_struct(entry), :plaintext)
  end
end
