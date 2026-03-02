defmodule SigilGuard.Vault.Entry do
  @moduledoc """
  Vault entry representing an encrypted secret.

  Matches the `VaultEntry` struct from the `sigil-protocol` Rust crate (v0.1.5).

  ## Fields

    * `:id` — unique vault identifier
    * `:ciphertext` — opaque encrypted data (binary)
    * `:description` — human-readable label for the secret
    * `:created_at` — ISO 8601 timestamp when the entry was created
    * `:tags` — list of categorization strings

  ## Example

      %SigilGuard.Vault.Entry{
        id: "vault_abc123",
        ciphertext: <<...>>,
        description: "OpenAI API key",
        created_at: "2026-03-02T10:00:00.000Z",
        tags: ["api_key", "openai"]
      }

  """

  @type t :: %__MODULE__{
          id: SigilGuard.Vault.vault_id() | nil,
          ciphertext: binary() | nil,
          description: String.t() | nil,
          created_at: String.t() | nil,
          tags: [String.t()]
        }

  defstruct [:id, :ciphertext, :description, :created_at, tags: []]
end
