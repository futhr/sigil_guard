defmodule SigilGuard.TestSigner do
  @moduledoc """
  Deterministic test signer with a fixed Ed25519 keypair.

  Uses a SHA-256 hash of a static seed string to derive a reproducible
  Ed25519 keypair. This ensures that envelope signatures and public keys
  are identical across test runs, making assertions on signed data stable.

  ## Usage

      envelope = SigilGuard.sign_envelope("did:sigil:test", :allowed,
        signer: SigilGuard.TestSigner
      )

      pub_key = SigilGuard.TestSigner.public_key_b64u()
      :ok = SigilGuard.verify_envelope(envelope, pub_key)

  """

  @behaviour SigilGuard.Signer

  # Fixed seed for deterministic test keypair
  @seed :crypto.hash(:sha256, "sigil_guard_test_seed_v1")

  @doc false
  @spec keypair() :: {binary(), binary()}
  def keypair do
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519, @seed)
    {pub, priv}
  end

  @impl SigilGuard.Signer
  def sign(message) do
    {_pub, priv} = keypair()
    :crypto.sign(:eddsa, :none, message, [priv, :ed25519])
  end

  @impl SigilGuard.Signer
  def public_key do
    {pub, _priv} = keypair()
    pub
  end

  @doc "Return the public key as base64url (no padding) for envelope verification."
  @spec public_key_b64u() :: String.t()
  def public_key_b64u do
    Base.url_encode64(public_key(), padding: false)
  end
end
