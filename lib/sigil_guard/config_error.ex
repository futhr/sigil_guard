defmodule SigilGuard.ConfigError do
  @moduledoc """
  Raised when SigilGuard configuration fails closed validation.
  """

  @type reason :: :legacy_contract_removed | :unknown_config_key | :invalid_config

  @type t :: %__MODULE__{
          key: atom(),
          reason: reason(),
          message: String.t()
        }

  defexception [:key, :reason, :message]

  @doc """
  Build a configuration error for an offending key.
  """
  @spec new(atom(), reason(), String.t()) :: t()
  def new(key, reason, detail) when is_atom(key) and is_atom(reason) and is_binary(detail) do
    %__MODULE__{
      key: key,
      reason: reason,
      message:
        "invalid :sigil_guard configuration for #{inspect(key)} " <>
          "(#{reason}): #{detail}; see MIGRATING-1.0.md"
    }
  end
end
