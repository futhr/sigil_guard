defmodule SigilGuard.Vault do
  @moduledoc """
  Secure vaulting behaviour and utilities for the SIGIL protocol.

  Provides an interface for encrypting, decrypting, and managing sensitive
  values (API keys, tokens, credentials) that should never appear in logs
  or tool call parameters.

  ## Behaviour

  Implement `SigilGuard.Vault` to provide a custom storage backend:

      defmodule MyApp.KmsVault do
        @behaviour SigilGuard.Vault

        @impl true
        def encrypt(plaintext, description) do
          # Encrypt via AWS KMS / GCP KMS / HashiCorp Vault
          {:ok, vault_id}
        end

        @impl true
        def decrypt(vault_id) do
          {:ok, plaintext}
        end

        @impl true
        def exists?(vault_id) do
          true
        end
      end

  ## Built-in Backend

  `SigilGuard.Vault.InMemory` provides an ETS-backed implementation
  using AES-256-GCM encryption. Suitable for development and testing.

  """

  @type vault_id :: String.t()

  @doc "Encrypt plaintext and store it, returning a vault ID for later retrieval."
  @callback encrypt(plaintext :: binary(), description :: String.t()) ::
              {:ok, vault_id()} | {:error, term()}

  @doc "Decrypt and return the plaintext for the given vault ID."
  @callback decrypt(vault_id()) :: {:ok, binary()} | {:error, term()}

  @doc "Check if a vault entry exists for the given ID."
  @callback exists?(vault_id()) :: boolean()

  @doc """
  Encrypt a value using the specified backend module.

  ## Examples

      {:ok, id} = SigilGuard.Vault.encrypt("sk-abc123", "OpenAI API key", MyVault)

  """
  @spec encrypt(binary(), String.t(), module()) :: {:ok, vault_id()} | {:error, term()}
  def encrypt(plaintext, description, backend) do
    backend.encrypt(plaintext, description)
  end

  @doc """
  Decrypt a value using the specified backend module.

  ## Examples

      {:ok, plaintext} = SigilGuard.Vault.decrypt("vault_abc123", MyVault)

  """
  @spec decrypt(vault_id(), module()) :: {:ok, binary()} | {:error, term()}
  def decrypt(vault_id, backend) do
    backend.decrypt(vault_id)
  end

  @doc """
  Check if a vault entry exists using the specified backend module.
  """
  @spec exists?(vault_id(), module()) :: boolean()
  def exists?(vault_id, backend) do
    backend.exists?(vault_id)
  end
end
