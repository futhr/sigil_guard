defmodule SigilGuard.Vault.InMemory do
  @moduledoc """
  ETS-backed in-memory vault using AES-256-GCM encryption.

  Suitable for development, testing, and single-node deployments.
  Data is lost on process/node restart.

  ## Usage

      # Start the vault (automatically creates ETS table)
      {:ok, _pid} = SigilGuard.Vault.InMemory.start_link([])

      # Store a secret
      {:ok, vault_id} = SigilGuard.Vault.InMemory.encrypt("my-secret", "API key")

      # Retrieve it
      {:ok, "my-secret"} = SigilGuard.Vault.InMemory.decrypt(vault_id)

  ## Encryption

  Each entry is encrypted with AES-256-GCM using a per-entry random IV.
  The encryption key is derived from a master key (configurable or auto-generated).

  Configure the master key:

      config :sigil_guard, :vault_master_key, "base64-encoded-32-byte-key"

  If not configured, a random key is generated on startup (entries won't
  survive restarts).

  """

  @behaviour SigilGuard.Vault

  use GenServer

  @table :sigil_guard_vault
  @aad "sigil_guard_vault_v1"

  # -- Client API --

  @doc "Start the in-memory vault GenServer."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl SigilGuard.Vault
  def encrypt(plaintext, description) do
    GenServer.call(__MODULE__, {:encrypt, plaintext, description})
  end

  @impl SigilGuard.Vault
  def decrypt(vault_id) do
    GenServer.call(__MODULE__, {:decrypt, vault_id})
  end

  @impl SigilGuard.Vault
  def exists?(vault_id) do
    GenServer.call(__MODULE__, {:exists?, vault_id})
  end

  @doc "List all vault entry IDs with their descriptions (not plaintext)."
  @spec list_entries() :: [{SigilGuard.Vault.vault_id(), String.t()}]
  def list_entries do
    GenServer.call(__MODULE__, :list_entries)
  end

  @doc "Delete a vault entry by ID."
  @spec delete(SigilGuard.Vault.vault_id()) :: :ok | {:error, :not_found}
  def delete(vault_id) do
    GenServer.call(__MODULE__, {:delete, vault_id})
  end

  # -- Server Callbacks --

  @impl GenServer
  def init(opts) do
    table = :ets.new(@table, [:named_table, :set, :private])

    master_key =
      Keyword.get_lazy(opts, :master_key, fn ->
        case Application.get_env(:sigil_guard, :vault_master_key) do
          nil -> :crypto.strong_rand_bytes(32)
          base64_key -> Base.decode64!(base64_key)
        end
      end)

    Process.flag(:sensitive, true)

    {:ok, %{table: table, master_key: master_key}}
  end

  @impl GenServer
  def handle_call({:encrypt, plaintext, description}, _, state) do
    vault_id = generate_vault_id()
    iv = :crypto.strong_rand_bytes(12)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(
        :aes_256_gcm,
        state.master_key,
        iv,
        plaintext,
        @aad,
        true
      )

    entry = %{
      ciphertext: ciphertext,
      iv: iv,
      tag: tag,
      description: description,
      created_at: DateTime.utc_now()
    }

    :ets.insert(state.table, {vault_id, entry})
    {:reply, {:ok, vault_id}, state}
  end

  @impl GenServer
  def handle_call({:decrypt, vault_id}, _, state) do
    result =
      case :ets.lookup(state.table, vault_id) do
        [{^vault_id, entry}] ->
          case :crypto.crypto_one_time_aead(
                 :aes_256_gcm,
                 state.master_key,
                 entry.iv,
                 entry.ciphertext,
                 @aad,
                 entry.tag,
                 false
               ) do
            plaintext when is_binary(plaintext) -> {:ok, plaintext}
            :error -> {:error, :decryption_failed}
          end

        [] ->
          {:error, :not_found}
      end

    {:reply, result, state}
  end

  @impl GenServer
  def handle_call({:exists?, vault_id}, _, state) do
    exists = :ets.member(state.table, vault_id)
    {:reply, exists, state}
  end

  @impl GenServer
  def handle_call(:list_entries, _, state) do
    entries =
      :ets.foldl(
        fn {id, entry}, acc -> [{id, entry.description} | acc] end,
        [],
        state.table
      )

    {:reply, entries, state}
  end

  @impl GenServer
  def handle_call({:delete, vault_id}, _, state) do
    result =
      if :ets.member(state.table, vault_id) do
        :ets.delete(state.table, vault_id)
        :ok
      else
        {:error, :not_found}
      end

    {:reply, result, state}
  end

  # Redact master key from crash dumps and :sys.get_status/1
  @impl GenServer
  def format_status(status) do
    %{status | state: %{status.state | master_key: :REDACTED}}
  end

  # -- Private --

  defp generate_vault_id do
    "vault_" <> Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)
  end
end
