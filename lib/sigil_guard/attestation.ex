defmodule SigilGuard.Attestation do
  @moduledoc """
  V3 attestation facade and reserved metadata helpers.

  The `_agent_trust` and `_agent_confirmation` keys carry SigilGuard trust
  evidence on guarded payloads. These helpers attach and fetch that metadata
  while `strip_metadata/1` applies the SP.01 digest strip rule before payload
  digest computation.
  """

  @trust_key "_agent_trust"
  @trust_atom_key :_agent_trust
  @confirmation_key "_agent_confirmation"
  @confirmation_atom_key :_agent_confirmation
  @confirmation_token_key "confirmation_token"
  @confirmation_token_atom_key :confirmation_token

  @strip_keys [
    @trust_key,
    @trust_atom_key,
    @confirmation_key,
    @confirmation_atom_key,
    @confirmation_token_key,
    @confirmation_token_atom_key
  ]

  @type payload :: map()
  @type envelope :: map()

  @doc """
  Attach an attestation envelope under the reserved `_agent_trust` key.

  Raises `ArgumentError` when `payload` is not a map.
  """
  @spec attach(payload(), envelope()) :: payload()
  def attach(payload, envelope) when is_map(payload) and is_map(envelope) do
    Map.put(payload, @trust_key, envelope)
  end

  def attach(payload, envelope) when is_map(payload) and not is_map(envelope) do
    raise ArgumentError, "expected attestation envelope to be a map, got: #{inspect(envelope)}"
  end

  def attach(payload, _) do
    raise ArgumentError, "expected attestation payload to be a map, got: #{inspect(payload)}"
  end

  @doc """
  Fetch an attestation envelope from `_agent_trust`.

  Both string and atom keys are accepted. Returns `:error` when the key is
  absent or the value is not a map.
  """
  @spec fetch(payload()) :: {:ok, envelope()} | :error
  def fetch(payload) when is_map(payload),
    do: fetch_map_metadata(payload, @trust_key, @trust_atom_key)

  def fetch(_), do: :error

  @doc """
  Attach a confirmation token under the reserved `_agent_confirmation` key.

  Raises `ArgumentError` when `payload` is not a map.
  """
  @spec attach_confirmation(payload(), String.t()) :: payload()
  def attach_confirmation(payload, token) when is_map(payload) and is_binary(token) do
    Map.put(payload, @confirmation_key, token)
  end

  def attach_confirmation(payload, token) when is_map(payload) do
    raise ArgumentError, "expected confirmation token to be a string, got: #{inspect(token)}"
  end

  def attach_confirmation(payload, _) do
    raise ArgumentError, "expected attestation payload to be a map, got: #{inspect(payload)}"
  end

  @doc """
  Fetch a confirmation token from `_agent_confirmation`.

  Both string and atom keys are accepted. Returns `:error` when the key is
  absent or the value is not a string.
  """
  @spec fetch_confirmation(payload()) :: {:ok, String.t()} | :error
  def fetch_confirmation(payload) when is_map(payload) do
    fetch_string_metadata(payload, @confirmation_key, @confirmation_atom_key)
  end

  def fetch_confirmation(_), do: :error

  @doc """
  Apply the SP.01 metadata strip rule.

  The six reserved keys are removed at the payload root and inside the map
  under `params` in both atom and string forms. Deeper nested occurrences and
  legacy `_sigil*` keys are left untouched.
  """
  @spec strip_metadata(term()) :: term()
  def strip_metadata(payload) when is_map(payload) do
    payload
    |> Map.drop(@strip_keys)
    |> strip_params_metadata(:params)
    |> strip_params_metadata("params")
  end

  def strip_metadata(payload) when is_list(payload) do
    Enum.map(payload, fn
      item when is_map(item) -> strip_metadata(item)
      item -> item
    end)
  end

  def strip_metadata(payload), do: payload

  defp strip_params_metadata(payload, params_key) do
    case Map.get(payload, params_key) do
      params when is_map(params) -> Map.put(payload, params_key, Map.drop(params, @strip_keys))
      _ -> payload
    end
  end

  defp fetch_map_metadata(payload, string_key, atom_key) do
    case fetch_metadata(payload, string_key, atom_key) do
      {:ok, value} when is_map(value) -> {:ok, value}
      _ -> :error
    end
  end

  defp fetch_string_metadata(payload, string_key, atom_key) do
    case fetch_metadata(payload, string_key, atom_key) do
      {:ok, value} when is_binary(value) -> {:ok, value}
      _ -> :error
    end
  end

  defp fetch_metadata(payload, string_key, atom_key) do
    case Map.fetch(payload, string_key) do
      {:ok, value} -> {:ok, value}
      :error -> Map.fetch(payload, atom_key)
    end
  end
end
