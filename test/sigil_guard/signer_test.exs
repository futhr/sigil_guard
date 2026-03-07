defmodule SigilGuard.SignerTest do
  @moduledoc """
  Tests for `SigilGuard.Signer` and `SigilGuard.Signer.Ed25519`.

  Covers keypair generation, signing, verification round-trips, and the
  Ed25519 default signer implementation.
  """

  use ExUnit.Case, async: true

  alias SigilGuard.Signer
  alias SigilGuard.Signer.Ed25519

  describe "generate_keypair/0" do
    test "returns a {public_key, private_key} tuple" do
      {pub, priv} = Signer.generate_keypair()

      assert byte_size(pub) == 32
      assert byte_size(priv) == 32
    end

    test "generates unique keypairs" do
      {pub1, _} = Signer.generate_keypair()
      {pub2, _} = Signer.generate_keypair()

      assert pub1 != pub2
    end
  end

  describe "Ed25519.new/1" do
    test "creates a signer struct from private key" do
      {_, priv} = Signer.generate_keypair()
      signer = Ed25519.new(priv)

      assert %Ed25519{} = signer
      assert byte_size(signer.public_key) == 32
      assert byte_size(signer.private_key) == 32
    end

    test "extracts correct public key from private key" do
      {pub, priv} = Signer.generate_keypair()
      signer = Ed25519.new(priv)

      assert signer.public_key == pub
    end
  end

  describe "Ed25519.sign_with/2" do
    test "produces a valid Ed25519 signature" do
      {pub, priv} = Signer.generate_keypair()
      signer = Ed25519.new(priv)
      message = "test message"

      signature = Ed25519.sign_with(signer, message)

      assert byte_size(signature) == 64
      assert Ed25519.verify(message, signature, pub)
    end

    test "different messages produce different signatures" do
      {_, priv} = Signer.generate_keypair()
      signer = Ed25519.new(priv)

      sig1 = Ed25519.sign_with(signer, "message one")
      sig2 = Ed25519.sign_with(signer, "message two")

      assert sig1 != sig2
    end

    test "signatures are deterministic for Ed25519" do
      {_, priv} = Signer.generate_keypair()
      signer = Ed25519.new(priv)
      message = "deterministic test"

      sig1 = Ed25519.sign_with(signer, message)
      sig2 = Ed25519.sign_with(signer, message)

      assert sig1 == sig2
    end
  end

  describe "Ed25519.verify/3" do
    test "returns true for valid signature" do
      {pub, priv} = Signer.generate_keypair()
      signer = Ed25519.new(priv)
      message = "valid message"
      signature = Ed25519.sign_with(signer, message)

      assert Ed25519.verify(message, signature, pub)
    end

    test "returns false for wrong message" do
      {pub, priv} = Signer.generate_keypair()
      signer = Ed25519.new(priv)
      signature = Ed25519.sign_with(signer, "original")

      refute Ed25519.verify("tampered", signature, pub)
    end

    test "returns false for wrong key" do
      {_, priv} = Signer.generate_keypair()
      {other_pub, _} = Signer.generate_keypair()
      signer = Ed25519.new(priv)
      signature = Ed25519.sign_with(signer, "message")

      refute Ed25519.verify("message", signature, other_pub)
    end

    test "returns false for tampered signature" do
      {pub, priv} = Signer.generate_keypair()
      signer = Ed25519.new(priv)
      signature = Ed25519.sign_with(signer, "message")

      # Flip a bit in the signature
      <<first_byte, rest::binary>> = signature
      tampered = <<Bitwise.bxor(first_byte, 1), rest::binary>>

      refute Ed25519.verify("message", tampered, pub)
    end
  end

  describe "Ed25519 Agent-based API" do
    test "sign/1 and public_key/0 work via Agent" do
      {_, priv} = Signer.generate_keypair()
      start_supervised!({Ed25519, private_key: priv})

      message = "agent test message"
      signature = Ed25519.sign(message)
      pub_key = Ed25519.public_key()

      assert byte_size(signature) == 64
      assert Ed25519.verify(message, signature, pub_key)
    end
  end
end
