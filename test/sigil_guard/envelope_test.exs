defmodule SigilGuard.EnvelopeTest do
  @moduledoc """
  Tests for `SigilGuard.Envelope`.

  Verifies canonical byte serialization, Ed25519 envelope signing and
  verification, nonce generation, and tamper detection. Uses the
  deterministic `SigilGuard.TestSigner` for reproducible assertions.
  """

  use ExUnit.Case, async: true

  alias SigilGuard.Envelope
  alias SigilGuard.TestSigner

  describe "canonical_bytes/4" do
    test "produces deterministic JSON with lexicographic key order" do
      bytes =
        Envelope.canonical_bytes(
          "did:sigil:alice",
          :allowed,
          "2024-01-01T00:00:00.000Z",
          "abcd1234"
        )

      assert bytes ==
               ~s({"identity":"did:sigil:alice","nonce":"abcd1234","timestamp":"2024-01-01T00:00:00.000Z","verdict":"allowed"})
    end

    test "keys are in strict lexicographic order" do
      bytes = Envelope.canonical_bytes("x", :blocked, "t", "n")
      decoded = Jason.decode!(bytes)
      keys = Map.keys(decoded)

      assert keys == Enum.sort(keys)
    end

    test "excludes signature and reason fields" do
      bytes = Envelope.canonical_bytes("id", :scanned, "ts", "nc")
      decoded = Jason.decode!(bytes)

      refute Map.has_key?(decoded, "signature")
      refute Map.has_key?(decoded, "reason")
    end

    test "formats verdict atoms as lowercase strings in canonical bytes" do
      for {atom, string} <- [{:allowed, "allowed"}, {:blocked, "blocked"}, {:scanned, "scanned"}] do
        bytes = Envelope.canonical_bytes("id", atom, "ts", "nc")
        decoded = Jason.decode!(bytes)
        assert decoded["verdict"] == string
      end
    end
  end

  describe "sign/3" do
    test "produces a valid envelope map" do
      envelope =
        Envelope.sign("did:sigil:test", :allowed,
          signer: TestSigner,
          timestamp: "2024-01-01T00:00:00.000Z",
          nonce: "deadbeef"
        )

      assert envelope["identity"] == "did:sigil:test"
      assert envelope["verdict"] == "Allowed"
      assert envelope["timestamp"] == "2024-01-01T00:00:00.000Z"
      assert envelope["nonce"] == "deadbeef"
      assert is_binary(envelope["signature"])
    end

    test "includes reason when provided" do
      envelope =
        Envelope.sign("did:sigil:test", :blocked,
          signer: TestSigner,
          reason: "sensitivity hit detected"
        )

      assert envelope["reason"] == "sensitivity hit detected"
    end

    test "excludes reason when not provided" do
      envelope = Envelope.sign("did:sigil:test", :allowed, signer: TestSigner)

      refute Map.has_key?(envelope, "reason")
    end

    test "signature is base64url-encoded without padding" do
      envelope = Envelope.sign("did:sigil:test", :allowed, signer: TestSigner)
      signature = envelope["signature"]

      refute String.contains?(signature, "=")
      refute String.contains?(signature, "+")
      refute String.contains?(signature, "/")
      assert {:ok, _} = Base.url_decode64(signature, padding: false)
    end

    test "generates timestamp and nonce when not provided" do
      envelope = Envelope.sign("did:sigil:test", :allowed, signer: TestSigner)

      assert String.ends_with?(envelope["timestamp"], "Z")
      assert byte_size(envelope["nonce"]) == 32
    end
  end

  describe "verify/2" do
    test "verifies a valid signature" do
      envelope =
        Envelope.sign("did:sigil:test", :allowed,
          signer: TestSigner,
          timestamp: "2024-06-15T10:30:00.000Z",
          nonce: "aabbccdd11223344"
        )

      assert :ok = Envelope.verify(envelope, TestSigner.public_key_b64u())
    end

    test "rejects tampered identity" do
      envelope =
        Envelope.sign("did:sigil:test", :allowed,
          signer: TestSigner,
          timestamp: "2024-06-15T10:30:00.000Z",
          nonce: "aabbccdd11223344"
        )

      tampered = Map.put(envelope, "identity", "did:sigil:evil")

      assert {:error, :invalid_signature} =
               Envelope.verify(tampered, TestSigner.public_key_b64u())
    end

    test "rejects tampered verdict" do
      envelope =
        Envelope.sign("did:sigil:test", :allowed,
          signer: TestSigner,
          timestamp: "2024-06-15T10:30:00.000Z",
          nonce: "aabbccdd11223344"
        )

      tampered = Map.put(envelope, "verdict", "Blocked")

      assert {:error, :invalid_signature} =
               Envelope.verify(tampered, TestSigner.public_key_b64u())
    end

    test "rejects tampered timestamp" do
      envelope =
        Envelope.sign("did:sigil:test", :allowed,
          signer: TestSigner,
          timestamp: "2024-06-15T10:30:00.000Z",
          nonce: "aabbccdd11223344"
        )

      tampered = Map.put(envelope, "timestamp", "2025-01-01T00:00:00.000Z")

      assert {:error, :invalid_signature} =
               Envelope.verify(tampered, TestSigner.public_key_b64u())
    end

    test "rejects wrong public key" do
      envelope = Envelope.sign("did:sigil:test", :allowed, signer: TestSigner)

      {other_pub, _} = :crypto.generate_key(:eddsa, :ed25519)
      other_b64u = Base.url_encode64(other_pub, padding: false)

      assert {:error, :invalid_signature} = Envelope.verify(envelope, other_b64u)
    end

    test "returns error for invalid base64 key" do
      envelope = Envelope.sign("did:sigil:test", :allowed, signer: TestSigner)

      assert {:error, :invalid_base64} = Envelope.verify(envelope, "not-valid-base64!!!")
    end

    test "returns error for invalid base64 in signature" do
      envelope =
        Envelope.sign("did:sigil:test", :allowed,
          signer: TestSigner,
          timestamp: "2024-06-15T10:30:00.000Z",
          nonce: "aabbccdd11223344"
        )

      bad_sig = Map.put(envelope, "signature", "not!valid!base64")
      assert {:error, :invalid_base64} = Envelope.verify(bad_sig, TestSigner.public_key_b64u())
    end

    test "verifies scanned verdict envelopes" do
      envelope =
        Envelope.sign("did:sigil:scanner", :scanned,
          signer: TestSigner,
          timestamp: "2024-06-15T10:30:00.000Z",
          nonce: "aabbccdd11223344"
        )

      assert envelope["verdict"] == "Scanned"
      assert :ok = Envelope.verify(envelope, TestSigner.public_key_b64u())
    end
  end

  describe "generate_timestamp/0" do
    test "returns ISO 8601 format with milliseconds" do
      ts = Envelope.generate_timestamp()

      assert String.ends_with?(ts, "Z")
      assert {:ok, _, _} = DateTime.from_iso8601(ts)
    end
  end

  describe "generate_nonce/0" do
    test "returns 32-character hex string (16 bytes)" do
      nonce = Envelope.generate_nonce()

      assert byte_size(nonce) == 32
      assert Regex.match?(~r/^[0-9a-f]{32}$/, nonce)
    end

    test "generates unique values" do
      nonces = for _ <- 1..100, do: Envelope.generate_nonce()

      assert length(Enum.uniq(nonces)) == 100
    end
  end
end
