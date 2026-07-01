defmodule SigilGuard.Audit.Anchor.ReceiptTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Audit.Anchor.Receipt
  alias SigilGuard.TestSigner

  @issuer "did:web:audit-receipts.example"

  describe "canonical_bytes/1 and digest/1" do
    test "canonicalizes nested maps deterministically and drops signature metadata" do
      receipt = %{
        "anchor_digest" => String.duplicate("a", 64),
        "metadata" => %{"z" => true, :a => :stored, 3 => ["x", nil]},
        "signature" => %{"signature" => "ignored"},
        version: 1
      }

      atom_signed = Map.put(Map.delete(receipt, "signature"), :signature, "ignored")

      assert Receipt.canonical_bytes(receipt) ==
               ~s({"anchor_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","metadata":{"3":["x",null],"a":"stored","z":true},"version":1})

      assert Receipt.canonical_bytes(receipt) == Receipt.canonical_bytes(atom_signed)
      assert Receipt.digest(receipt) == Receipt.digest(atom_signed)
    end

    test "unsigned/1 removes string and atom signature metadata" do
      receipt = %{"anchor_digest" => "digest", "signature" => "string", signature: "atom"}

      assert Receipt.unsigned(receipt) == %{"anchor_digest" => "digest"}
    end
  end

  describe "sign/3 and verify/2" do
    test "signs receipts and verifies them by issuer public key" do
      receipt = receipt_fixture()

      signed = Receipt.sign(receipt, TestSigner, issuer: @issuer)

      assert signed["signature"]["issuer"] == @issuer
      assert signed["signature"]["algorithm"] == "Ed25519"
      assert signed["signature"]["digest"] == Receipt.digest(receipt)
      assert byte_size(signed["signature"]["signature"]) > 0

      assert :ok =
               Receipt.verify(signed,
                 public_keys: %{@issuer => TestSigner.public_key_b64u()}
               )
    end

    test "verifies with atom-keyed signature metadata and standard base64 keys" do
      signed =
        receipt_fixture()
        |> Receipt.sign(TestSigner, issuer: @issuer)
        |> atomize_signature()

      assert :ok = Receipt.verify(signed, public_key_b64u: Base.encode64(TestSigner.public_key()))
    end

    test "rejects unsigned, malformed, and non-map receipts cleanly" do
      assert {:error, :unsigned_receipt} = Receipt.verify(receipt_fixture())
      assert {:error, :invalid_signature_metadata} = Receipt.verify(%{"signature" => false})
      assert {:error, :invalid_receipt} = Receipt.verify("bad")
    end

    test "rejects incomplete or unsupported signature metadata" do
      signed = Receipt.sign(receipt_fixture(), TestSigner, issuer: @issuer)

      for {field, reason} <- [
            {"issuer", :missing_issuer},
            {"algorithm", :missing_algorithm},
            {"digest", :missing_digest},
            {"signature", :missing_signature}
          ] do
        assert {:error, ^reason} =
                 signed
                 |> update_in(["signature"], &Map.delete(&1, field))
                 |> Receipt.verify()

        assert {:error, ^reason} =
                 signed
                 |> put_in(["signature", field], "")
                 |> Receipt.verify(public_key_b64u: TestSigner.public_key_b64u())
      end

      assert {:error, :unsupported_algorithm} =
               signed
               |> put_in(["signature", "algorithm"], "Ed448")
               |> Receipt.verify()
    end

    test "rejects tampered receipts, digests, signatures, and key material" do
      signed = Receipt.sign(receipt_fixture(), TestSigner, issuer: @issuer)
      opts = [public_keys: %{@issuer => TestSigner.public_key_b64u()}]

      assert {:error, :digest_mismatch} =
               signed
               |> put_in(["anchor_digest"], String.duplicate("b", 64))
               |> Receipt.verify(opts)

      assert {:error, :digest_mismatch} =
               signed
               |> put_in(["signature", "digest"], String.duplicate("0", 64))
               |> Receipt.verify(opts)

      assert {:error, :invalid_signature} =
               signed
               |> put_in(["signature", "signature"], Base.url_encode64("short", padding: false))
               |> Receipt.verify(opts)

      assert {:error, :invalid_base64} =
               signed
               |> put_in(["signature", "signature"], "not!base64")
               |> Receipt.verify(opts)

      assert {:error, :unknown_issuer} = Receipt.verify(signed)
      assert {:error, :invalid_public_keys} = Receipt.verify(signed, public_keys: "bad")

      assert {:error, :invalid_key} =
               Receipt.verify(signed, public_key_b64u: Base.encode64("short"))

      assert {:error, :invalid_base64} = Receipt.verify(signed, public_key_b64u: "not!base64")

      wrong_key = Base.url_encode64(:binary.copy(<<0>>, 32), padding: false)

      assert {:error, :invalid_signature} =
               Receipt.verify(signed, public_key_b64u: wrong_key)
    end
  end

  test "signature/1 preserves invalid string-keyed signature metadata" do
    assert Receipt.signature(%{"signature" => false, signature: %{"signature" => "atom"}}) ==
             false
  end

  defp receipt_fixture do
    %{
      "kind" => "sigil_guard.audit.anchor.receipt",
      "version" => 1,
      "storage" => "worm_gateway",
      "uri" => "https://audit.example.test/anchors/abc",
      "anchor_digest" => String.duplicate("a", 64),
      "stored_at" => "2026-01-01T00:00:00.000Z",
      "worm" => true,
      "metadata" => %{"region" => "eu", "replicas" => ["a", "b"]}
    }
  end

  defp atomize_signature(receipt) do
    signature =
      receipt
      |> Map.fetch!("signature")
      |> Enum.map(fn {key, value} -> {String.to_existing_atom(key), value} end)
      |> Map.new()

    receipt
    |> Map.delete("signature")
    |> Map.put(:signature, signature)
  end
end
