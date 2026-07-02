defmodule SigilGuard.Vault.InMemory do
  @moduledoc """
  ETS-backed in-memory vault using AES-256-GCM encryption.

  Suitable for development, testing, and single-node deployments.
  Entries live in a private ETS table owned by the vault process and
  are lost when it stops — **no entry survives a restart, with or
  without a configured master key**. For durable secrets, implement
  `SigilGuard.Vault` against persistent storage.

  ## Usage

      # Start the vault (automatically creates ETS table)
      {:ok, _pid} = SigilGuard.Vault.InMemory.start_link([])

      # Store a secret
      {:ok, vault_id} = SigilGuard.Vault.InMemory.encrypt("my-secret", "API key")

      # Retrieve it
      {:ok, "my-secret"} = SigilGuard.Vault.InMemory.decrypt(vault_id)

  ## Encryption

  Each entry is encrypted with AES-256-GCM using a per-entry random IV.
  The key is taken from the `:master_key` start option, then the
  `:vault_master_key` application env (base64-encoded 32 bytes), and
  otherwise randomly generated at startup:

      config :sigil_guard, :vault_master_key, "base64-encoded-32-byte-key"

  A configured key gives you stable key material across restarts; it
  does not make the (in-memory) entries themselves persistent.

  ## Process Model

  `start_link/1` registers a singleton GenServer under
  `#{inspect(__MODULE__)}` — one vault per node. Supervise it in your
  application's tree; the `SigilGuard.Vault` callbacks exit if it is
  not running.
  """

  @behaviour SigilGuard.Vault

  use GenServer

  @table :sigil_guard_vault
  @aad "sigil_guard_vault_v1"
  @master_key_bytes 32
  @start_schema [
    master_key: [
      type: {:custom, __MODULE__, :validate_master_key_option, []},
      doc: "Raw 32-byte AES-256-GCM master key."
    ]
  ]

  # -- Client API --

  @doc "Start the in-memory vault GenServer."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Return generated documentation for start options.
  """
  @spec start_options_docs() :: String.t()
  def start_options_docs do
    NimbleOptions.docs(@start_schema)
  end

  @doc false
  @spec validate_master_key_option(term()) :: {:ok, term()}
  def validate_master_key_option(master_key), do: {:ok, master_key}

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
    Process.flag(:sensitive, true)

    with {:ok, validated} <- validate_start_options(opts),
         {:ok, master_key} <- master_key(validated) do
      table = :ets.new(@table, [:named_table, :set, :private])
      {:ok, %{table: table, master_key: master_key}}
    else
      {:error, reason} -> {:stop, reason}
    end
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

  defp validate_start_options(opts) when is_list(opts) do
    if Keyword.keyword?(opts) do
      validate_start_keyword_options(opts)
    else
      {:error, :invalid_options}
    end
  end

  defp validate_start_options(_), do: {:error, :invalid_options}

  defp validate_start_keyword_options(opts) do
    case NimbleOptions.validate(opts, @start_schema) do
      {:ok, validated} -> {:ok, validated}
      {:error, %NimbleOptions.ValidationError{}} -> {:error, :invalid_options}
    end
  end

  defp master_key(opts) do
    case Keyword.fetch(opts, :master_key) do
      {:ok, key} -> validate_master_key(key)
      :error -> configured_master_key()
    end
  end

  defp configured_master_key do
    case Application.get_env(:sigil_guard, :vault_master_key) do
      nil -> {:ok, :crypto.strong_rand_bytes(@master_key_bytes)}
      key when is_binary(key) -> decode_configured_master_key(key)
      _ -> {:error, {:invalid_master_key, :invalid_type}}
    end
  end

  defp decode_configured_master_key(key) do
    case Base.decode64(key) do
      {:ok, decoded} -> validate_master_key(decoded)
      :error -> {:error, {:invalid_master_key, :invalid_base64}}
    end
  end

  defp validate_master_key(key) when is_binary(key) and byte_size(key) == @master_key_bytes do
    {:ok, key}
  end

  defp validate_master_key(key) when is_binary(key) do
    {:error, {:invalid_master_key, :invalid_length}}
  end

  defp validate_master_key(_) do
    {:error, {:invalid_master_key, :invalid_type}}
  end
end
