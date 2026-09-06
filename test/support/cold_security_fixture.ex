defmodule SigilGuard.ColdSecurityFixture do
  @moduledoc false
  @behaviour SigilGuard.Signer

  @doc false
  @spec on_tool_request(term(), term()) :: {:block, String.t()}
  def on_tool_request(_, _), do: {:block, "cold hook denied"}

  @impl SigilGuard.Signer
  def public_key do
    {key, _} = :crypto.generate_key(:eddsa, :ed25519, :binary.copy(<<42>>, 32))
    key
  end

  @impl SigilGuard.Signer
  def sign(bytes) do
    {_, key} = :crypto.generate_key(:eddsa, :ed25519, :binary.copy(<<42>>, 32))
    :crypto.sign(:eddsa, :none, bytes, [key, :ed25519])
  end
end
