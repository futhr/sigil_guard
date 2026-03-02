defmodule SigilGuard.Signer.Ed25519 do
  @moduledoc """
  Default Ed25519 signer using OTP `:crypto`.

  Holds a keypair in process state. For production use, consider implementing
  `SigilGuard.Signer` with an HSM or KMS backend instead.

  ## Usage

      {pub, priv} = SigilGuard.Signer.generate_keypair()
      signer = SigilGuard.Signer.Ed25519.new(priv)
      signature = signer.sign.(message)

  Or use as a module-based signer via `start_link/1`:

      {:ok, _pid} = SigilGuard.Signer.Ed25519.start_link(private_key: priv)
      signature = SigilGuard.Signer.Ed25519.sign(message)

  """

  @behaviour SigilGuard.Signer

  use Agent

  @type t :: %__MODULE__{
          private_key: binary(),
          public_key: binary()
        }

  defstruct [:private_key, :public_key]

  @doc """
  Create a signer struct from a private key (seed).

  Accepts the raw 32-byte Ed25519 seed as returned by `:crypto.generate_key/2`.
  Derives the public key from the seed.
  """
  @spec new(binary()) :: t()
  def new(private_key) when byte_size(private_key) == 32 do
    {public_key, _priv} = :crypto.generate_key(:eddsa, :ed25519, private_key)

    %__MODULE__{
      private_key: private_key,
      public_key: public_key
    }
  end

  @doc """
  Start a named agent holding the keypair for module-based callback usage.
  """
  @spec start_link(keyword()) :: Agent.on_start()
  def start_link(opts) do
    private_key = Keyword.fetch!(opts, :private_key)
    signer = new(private_key)
    Agent.start_link(fn -> signer end, name: __MODULE__)
  end

  @impl SigilGuard.Signer
  def sign(message) do
    signer = Agent.get(__MODULE__, & &1)
    sign_with(signer, message)
  end

  @impl SigilGuard.Signer
  def public_key do
    Agent.get(__MODULE__, & &1.public_key)
  end

  @doc "Sign a message using a signer struct (without requiring the Agent)."
  @spec sign_with(t(), binary()) :: binary()
  def sign_with(%__MODULE__{private_key: priv}, message) do
    :crypto.sign(:eddsa, :none, message, [priv, :ed25519])
  end

  @doc "Verify a signature using a raw public key."
  @spec verify(binary(), binary(), binary()) :: boolean()
  def verify(message, signature, public_key) do
    :crypto.verify(:eddsa, :none, message, signature, [public_key, :ed25519])
  end
end
