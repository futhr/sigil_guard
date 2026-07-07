defmodule SigilGuard.Signer.Ed25519Test do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Signer
  alias SigilGuard.Signer.Ed25519

  test "derives the public key from a valid private key seed" do
    {public_key, private_key} = Signer.generate_keypair()

    assert %Ed25519{public_key: ^public_key, private_key: ^private_key} = Ed25519.new(private_key)
  end

  test "signs and verifies without the singleton process" do
    {public_key, private_key} = Signer.generate_keypair()
    signer = Ed25519.new(private_key)
    signature = Ed25519.sign_with(signer, "message")

    assert Ed25519.verify("message", signature, public_key)
    refute Ed25519.verify("tampered", signature, public_key)
  end

  test "validates singleton start options fail closed" do
    assert {:error, :invalid_options} = Ed25519.start_link(:bad)
    assert {:error, :missing_private_key} = Ed25519.start_link([])
    assert {:error, :invalid_private_key} = Ed25519.start_link(private_key: "short")
  end
end
