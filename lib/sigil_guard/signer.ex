defmodule SigilGuard.Signer do
  @moduledoc """
  Behaviour for signing operations in the SIGIL protocol.

  Implementations produce Ed25519 signatures over canonical envelope bytes.
  The two required callbacks are `c:sign/1` and `c:public_key/0`.

  ## Usage

  Pass your signer module to envelope operations:

      SigilGuard.sign_envelope("did:sigil:example", :allowed,
        signer: MyApp.HsmSigner
      )

  ## Implementing a Custom Signer

  Any module implementing this behaviour can be used for envelope signing.
  Common use cases include HSM-backed keys, cloud KMS, or hardware tokens:

      defmodule MyApp.HsmSigner do
        @behaviour SigilGuard.Signer

        @impl true
        def sign(message) do
          # Sign via HSM or KMS
          MyHsm.sign(:ed25519, message)
        end

        @impl true
        def public_key do
          MyHsm.public_key(:ed25519)
        end
      end

  ## Keypair Generation

  For development and testing, use `generate_keypair/0` to create an
  ephemeral Ed25519 keypair:

      {pub, priv} = SigilGuard.Signer.generate_keypair()

  """

  @doc "Sign the given message bytes, returning a raw Ed25519 signature."
  @callback sign(message :: binary()) :: binary()

  @doc "Return the raw Ed25519 public key (32 bytes)."
  @callback public_key() :: binary()

  @doc """
  Generate a new Ed25519 keypair.

  Returns `{public_key, private_key}` where both are raw 32-byte binaries.
  The private key is the Ed25519 seed as returned by OTP `:crypto`.
  """
  @spec generate_keypair() :: {public_key :: binary(), private_key :: binary()}
  def generate_keypair do
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
    {pub, priv}
  end
end
