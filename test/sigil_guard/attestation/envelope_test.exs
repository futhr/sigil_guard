defmodule SigilGuard.Attestation.EnvelopeTest do
  use ExUnit.Case, async: true

  alias __MODULE__.MissingSigner
  alias __MODULE__.RaisingPublicKeySigner
  alias __MODULE__.RaisingSignatureSigner
  alias __MODULE__.ShortPublicKeySigner
  alias __MODULE__.ShortSignatureSigner
  alias __MODULE__.SignerA
  alias __MODULE__.SignerB
  alias SigilGuard.Attestation.Envelope

  describe "pae/2" do
    test "emits the exact DSSE pre-authentication bytes" do
      assert Envelope.pae("application/vnd.sigilguard+json", ~s({"x":1})) ==
               ~s(DSSEv1 31 application/vnd.sigilguard+json 7 {"x":1})
    end
  end

  describe "sign/3 and verify/2" do
    test "signs and verifies an envelope" do
      payload = ~s({"statement":"bytes"})

      assert {:ok, envelope} = Envelope.sign(payload, SignerA)
      assert envelope["payloadType"] == "application/vnd.sigilguard+json"
      assert envelope["payload"] == Base.url_encode64(payload, padding: false)
      assert [%{"keyid" => keyid, "sig" => sig}] = envelope["signatures"]
      assert keyid == Envelope.keyid(SignerA.public_key())
      assert {:ok, decoded_sig} = Base.url_decode64(sig, padding: false)
      assert byte_size(decoded_sig) == 64

      assert Envelope.verify(envelope, %{keyid => SignerA.public_key()}) == {:ok, payload}
    end

    test "honors an explicit keyid" do
      assert {:ok, envelope} = Envelope.sign("payload", SignerA, keyid: "test-key")

      assert Envelope.verify(envelope, %{"test-key" => SignerA.public_key()}) == {:ok, "payload"}
    end

    test "multi-signature envelopes verify when all resolved signatures are valid" do
      payload = ~s({"statement":"bytes"})

      assert {:ok, envelope} =
               Envelope.sign_many(payload, [{SignerA, "a-key"}, {SignerB, "b-key"}])

      assert Envelope.verify(envelope, %{
               "a-key" => Base.url_encode64(SignerA.public_key(), padding: false),
               "b-key" => SignerB.public_key()
             }) == {:ok, payload}
    end

    test "unresolved witness signatures are tolerated when another key resolves" do
      assert {:ok, envelope} =
               Envelope.sign_many("payload", [{SignerA, "a-key"}, {SignerB, "b-key"}])

      assert Envelope.verify(envelope, %{"a-key" => SignerA.public_key()}) == {:ok, "payload"}
    end

    test "accepts bare signer modules and atom-key envelope shapes" do
      assert {:ok, envelope} = Envelope.sign_many("payload", [SignerA])
      [signature] = envelope["signatures"]
      keyid = signature["keyid"]

      atom_envelope = %{
        payload: envelope["payload"],
        payloadType: envelope["payloadType"],
        signatures: [%{keyid: keyid, sig: signature["sig"]}]
      }

      assert Envelope.verify(atom_envelope, %{keyid => SignerA.public_key()}) == {:ok, "payload"}
    end

    test "returns unknown_key_id when no signature key resolves" do
      assert {:ok, envelope} = Envelope.sign("payload", SignerA, keyid: "a-key")

      assert Envelope.verify(envelope, %{"other-key" => SignerA.public_key()}) ==
               {:error, :unknown_key_id}
    end

    test "detects a flipped payload byte as invalid_signature" do
      assert {:ok, envelope} = Envelope.sign("payload", SignerA, keyid: "a-key")

      tampered = %{envelope | "payload" => Base.url_encode64("qayload", padding: false)}

      assert Envelope.verify(tampered, %{"a-key" => SignerA.public_key()}) ==
               {:error, :invalid_signature}
    end

    test "detects a tampered signature as invalid_signature" do
      assert {:ok, envelope} = Envelope.sign("payload", SignerA, keyid: "a-key")
      [signature] = envelope["signatures"]

      tampered_signature = %{
        signature
        | "sig" => Base.url_encode64(:binary.copy(<<0>>, 64), padding: false)
      }

      tampered = %{envelope | "signatures" => [tampered_signature]}

      assert Envelope.verify(tampered, %{"a-key" => SignerA.public_key()}) ==
               {:error, :invalid_signature}
    end
  end

  describe "verify/2 negatives" do
    test "rejects non-map and badly typed envelopes" do
      assert Envelope.verify("bad", %{}) == {:error, :invalid_envelope}
      assert Envelope.verify(%{}, %{}) == {:error, :invalid_envelope}

      assert Envelope.verify(
               %{"payload" => "x", "payloadType" => Envelope.payload_type(), "signatures" => []},
               %{}
             ) == {:error, :invalid_envelope}

      assert Envelope.verify(
               %{
                 "payload" => "x",
                 "payloadType" => Envelope.payload_type(),
                 "signatures" => [%{"keyid" => "k"}]
               },
               %{}
             ) == {:error, :invalid_envelope}

      assert Envelope.verify(
               %{
                 "payload" => "x",
                 "payloadType" => Envelope.payload_type(),
                 "signatures" => ["bad"]
               },
               %{}
             ) == {:error, :invalid_envelope}
    end

    test "rejects wrong payloadType" do
      assert {:ok, envelope} = Envelope.sign("payload", SignerA)
      tampered = %{envelope | "payloadType" => "application/json"}

      assert Envelope.verify(tampered, %{}) == {:error, :invalid_payload_type}
    end

    test "rejects undecodable base64 payloads and signatures" do
      assert {:ok, envelope} = Envelope.sign("payload", SignerA, keyid: "a-key")

      assert Envelope.verify(%{envelope | "payload" => "not base64!"}, %{
               "a-key" => SignerA.public_key()
             }) ==
               {:error, :invalid_base64}

      [signature] = envelope["signatures"]
      tampered = %{envelope | "signatures" => [%{signature | "sig" => "not base64!"}]}

      assert Envelope.verify(tampered, %{"a-key" => SignerA.public_key()}) ==
               {:error, :invalid_base64}

      assert Envelope.verify(%{envelope | "payload" => 42}, %{"a-key" => SignerA.public_key()}) ==
               {:error, :invalid_envelope}
    end

    test "rejects duplicate keyids before verification" do
      assert {:ok, envelope} =
               Envelope.sign_many("payload", [{SignerA, "same"}, {SignerB, "same"}])

      assert Envelope.verify(envelope, %{"same" => SignerA.public_key()}) ==
               {:error, :duplicate_keyid}
    end

    test "rejects invalid trust material shape" do
      assert {:ok, envelope} = Envelope.sign("payload", SignerA)

      assert Envelope.verify(envelope, "bad") == {:error, :missing_trust_bundle}
    end

    test "rejects malformed public keys and short signatures as invalid signatures" do
      assert {:ok, envelope} = Envelope.sign("payload", SignerA, keyid: "a-key")

      assert Envelope.verify(envelope, %{"a-key" => :bad}) == {:error, :invalid_signature}

      assert Envelope.verify(envelope, %{
               "a-key" => Base.url_encode64("too-short", padding: false)
             }) == {:error, :invalid_signature}

      assert Envelope.verify(envelope, %{"a-key" => "not base64!"}) ==
               {:error, :invalid_signature}

      [signature] = envelope["signatures"]

      short_signature = %{
        envelope
        | "signatures" => [
            %{signature | "sig" => Base.url_encode64("too-short", padding: false)}
          ]
      }

      assert Envelope.verify(short_signature, %{"a-key" => SignerA.public_key()}) ==
               {:error, :invalid_signature}
    end
  end

  describe "sign/3 negatives" do
    test "rejects invalid payloads and signers" do
      assert Envelope.sign(:not_binary, SignerA) == {:error, :invalid_envelope}
      assert Envelope.sign("payload", MissingSigner) == {:error, :invalid_signer}
      assert Envelope.sign_many("payload", []) == {:error, :invalid_envelope}
      assert Envelope.sign_many("payload", ["bad"]) == {:error, :invalid_signer}
      assert Envelope.sign("payload", SignerA, keyid: "") == {:error, :invalid_signer}
      assert Envelope.sign("payload", ShortPublicKeySigner) == {:error, :invalid_signer}
      assert Envelope.sign("payload", RaisingPublicKeySigner) == {:error, :invalid_signer}
      assert Envelope.sign("payload", ShortSignatureSigner) == {:error, :invalid_signer}
      assert Envelope.sign("payload", RaisingSignatureSigner) == {:error, :invalid_signer}
    end
  end

  defmodule SignerA do
    @behaviour SigilGuard.Signer

    @seed :crypto.hash(:sha256, "sigilguard-dsse-signer-a")

    @impl SigilGuard.Signer
    def sign(message) do
      {_, private_key} = keypair()
      :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])
    end

    @impl SigilGuard.Signer
    def public_key do
      {public_key, _} = keypair()
      public_key
    end

    defp keypair do
      :crypto.generate_key(:eddsa, :ed25519, @seed)
    end
  end

  defmodule SignerB do
    @behaviour SigilGuard.Signer

    @seed :crypto.hash(:sha256, "sigilguard-dsse-signer-b")

    @impl SigilGuard.Signer
    def sign(message) do
      {_, private_key} = keypair()
      :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])
    end

    @impl SigilGuard.Signer
    def public_key do
      {public_key, _} = keypair()
      public_key
    end

    defp keypair do
      :crypto.generate_key(:eddsa, :ed25519, @seed)
    end
  end

  defmodule MissingSigner do
  end

  defmodule ShortPublicKeySigner do
    @behaviour SigilGuard.Signer

    @impl SigilGuard.Signer
    def sign(_), do: :binary.copy(<<0>>, 64)

    @impl SigilGuard.Signer
    def public_key, do: "too-short"
  end

  defmodule RaisingPublicKeySigner do
    @behaviour SigilGuard.Signer

    @impl SigilGuard.Signer
    def sign(_), do: :binary.copy(<<0>>, 64)

    @impl SigilGuard.Signer
    def public_key, do: raise("boom")
  end

  defmodule ShortSignatureSigner do
    @behaviour SigilGuard.Signer

    @seed :crypto.hash(:sha256, "sigilguard-short-signature")

    @impl SigilGuard.Signer
    def sign(_), do: "too-short"

    @impl SigilGuard.Signer
    def public_key do
      {public_key, _} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      public_key
    end
  end

  defmodule RaisingSignatureSigner do
    @behaviour SigilGuard.Signer

    @seed :crypto.hash(:sha256, "sigilguard-raising-signature")

    @impl SigilGuard.Signer
    def sign(_), do: raise("boom")

    @impl SigilGuard.Signer
    def public_key do
      {public_key, _} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      public_key
    end
  end
end
