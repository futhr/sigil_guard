defmodule SigilGuard.VaultTest do
  @moduledoc """
  Tests for `SigilGuard.Vault` and `SigilGuard.Vault.InMemory`.

  Exercises the vaulting lifecycle: store, retrieve, delete, and list
  operations on the ETS-backed in-memory vault with AES-256-GCM encryption.
  """

  use ExUnit.Case, async: false

  alias SigilGuard.Vault.InMemory

  setup do
    master_key = :crypto.strong_rand_bytes(32)
    start_supervised!({InMemory, master_key: master_key})
    %{master_key: master_key}
  end

  describe "encrypt/2 and decrypt/1" do
    test "round-trips plaintext" do
      {:ok, vault_id} = InMemory.encrypt("my-secret-key", "API key")
      {:ok, plaintext} = InMemory.decrypt(vault_id)

      assert plaintext == "my-secret-key"
    end

    test "handles binary data" do
      binary = :crypto.strong_rand_bytes(256)
      {:ok, vault_id} = InMemory.encrypt(binary, "random bytes")
      {:ok, decrypted} = InMemory.decrypt(vault_id)

      assert decrypted == binary
    end

    test "handles empty string" do
      {:ok, vault_id} = InMemory.encrypt("", "empty secret")
      {:ok, plaintext} = InMemory.decrypt(vault_id)

      assert plaintext == ""
    end

    test "handles unicode text" do
      secret = "пароль_тест_日本語"
      {:ok, vault_id} = InMemory.encrypt(secret, "unicode secret")
      {:ok, plaintext} = InMemory.decrypt(vault_id)

      assert plaintext == secret
    end

    test "each encryption produces a unique vault ID" do
      ids =
        for _i <- 1..50 do
          {:ok, id} = InMemory.encrypt("same-secret", "test")
          id
        end

      assert length(Enum.uniq(ids)) == 50
    end

    test "vault IDs have expected format" do
      {:ok, vault_id} = InMemory.encrypt("secret", "test")

      assert String.starts_with?(vault_id, "vault_")
      assert byte_size(vault_id) == 6 + 32
    end
  end

  describe "decrypt/1 errors" do
    test "returns error for non-existent vault ID" do
      assert {:error, :not_found} = InMemory.decrypt("vault_nonexistent")
    end

    test "returns error when decryption fails due to corrupted data" do
      {:ok, vault_id} = InMemory.encrypt("my-secret", "test")

      # Corrupt the ETS entry from inside the GenServer process (ETS table is :private)
      :sys.replace_state(InMemory, fn state ->
        [{^vault_id, entry}] = :ets.lookup(state.table, vault_id)
        corrupted = %{entry | tag: :crypto.strong_rand_bytes(16)}
        :ets.insert(state.table, {vault_id, corrupted})
        state
      end)

      assert {:error, :decryption_failed} = InMemory.decrypt(vault_id)
    end
  end

  describe "exists?/1" do
    test "returns true for existing entries" do
      {:ok, vault_id} = InMemory.encrypt("secret", "test")

      assert InMemory.exists?(vault_id)
    end

    test "returns false for non-existent entries" do
      refute InMemory.exists?("vault_doesnotexist")
    end
  end

  describe "list_entries/0" do
    test "returns empty list initially" do
      assert [] = InMemory.list_entries()
    end

    test "lists stored entries with IDs and descriptions" do
      {:ok, id1} = InMemory.encrypt("secret1", "First key")
      {:ok, id2} = InMemory.encrypt("secret2", "Second key")

      entries = InMemory.list_entries()

      assert length(entries) == 2
      assert {id1, "First key"} in entries
      assert {id2, "Second key"} in entries
    end
  end

  describe "delete/1" do
    test "removes an existing entry" do
      {:ok, vault_id} = InMemory.encrypt("secret", "to delete")

      assert :ok = InMemory.delete(vault_id)
      refute InMemory.exists?(vault_id)
      assert {:error, :not_found} = InMemory.decrypt(vault_id)
    end

    test "returns error for non-existent entry" do
      assert {:error, :not_found} = InMemory.delete("vault_nope")
    end
  end

  describe "encryption isolation" do
    test "different entries decrypt independently" do
      {:ok, id1} = InMemory.encrypt("alpha", "first")
      {:ok, id2} = InMemory.encrypt("beta", "second")
      {:ok, id3} = InMemory.encrypt("gamma", "third")

      assert {:ok, "alpha"} = InMemory.decrypt(id1)
      assert {:ok, "beta"} = InMemory.decrypt(id2)
      assert {:ok, "gamma"} = InMemory.decrypt(id3)
    end
  end

  describe "master key from application config" do
    test "uses auto-generated key when no config and no opt" do
      stop_supervised!(InMemory)
      Application.delete_env(:sigil_guard, :vault_master_key)
      start_supervised!(InMemory)

      {:ok, vault_id} = InMemory.encrypt("test", "auto-key")
      {:ok, "test"} = InMemory.decrypt(vault_id)
    end

    test "uses base64-encoded key from application config" do
      stop_supervised!(InMemory)
      key = :crypto.strong_rand_bytes(32)
      Application.put_env(:sigil_guard, :vault_master_key, Base.encode64(key))

      start_supervised!(InMemory)

      {:ok, vault_id} = InMemory.encrypt("config-test", "from config")
      {:ok, "config-test"} = InMemory.decrypt(vault_id)

      Application.delete_env(:sigil_guard, :vault_master_key)
    end
  end

  describe "SigilGuard.Vault facade" do
    test "encrypt/3 delegates to backend" do
      {:ok, vault_id} = SigilGuard.Vault.encrypt("test", "desc", InMemory)

      assert is_binary(vault_id)
    end

    test "decrypt/2 delegates to backend" do
      {:ok, vault_id} = SigilGuard.Vault.encrypt("facade_test", "desc", InMemory)
      {:ok, plaintext} = SigilGuard.Vault.decrypt(vault_id, InMemory)

      assert plaintext == "facade_test"
    end

    test "exists?/2 delegates to backend" do
      {:ok, vault_id} = SigilGuard.Vault.encrypt("test", "desc", InMemory)

      assert SigilGuard.Vault.exists?(vault_id, InMemory)
      refute SigilGuard.Vault.exists?("vault_nope", InMemory)
    end
  end
end
