defmodule SigilGuard.Registry.BundleTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Registry.Bundle
  alias SigilGuard.TestSigner

  @issuer "did:sigil:registry"
  @issued_at "2026-06-30T12:00:00.000Z"

  defp bundle do
    %{
      "generated_at" => "2026-06-30T12:00:00Z",
      "patterns" => [
        %{
          "name" => "registry_pat",
          "regex" => "REG_[0-9]+",
          "category" => "test",
          "severity" => "low"
        }
      ]
    }
  end

  describe "canonical_bytes/1" do
    test "is stable and excludes provenance metadata" do
      signed = Bundle.sign(bundle(), TestSigner, issuer: @issuer, issued_at: @issued_at)

      assert Bundle.canonical_bytes(signed) == Bundle.canonical_bytes(bundle())
      assert Bundle.digest(signed) == Bundle.digest(bundle())
    end
  end

  describe "sign/3 and verify/2" do
    test "signs and verifies bundle provenance" do
      signed = Bundle.sign(bundle(), TestSigner, issuer: @issuer, issued_at: @issued_at)

      assert {:ok, verified} =
               Bundle.verify(signed, public_keys: %{@issuer => TestSigner.public_key_b64u()})

      assert verified.status == :verified
      assert verified.issuer == @issuer
      assert verified.bundle == bundle()
      assert verified.provenance["issued_at"] == @issued_at
      assert is_binary(verified.digest)
    end

    test "accepts unsigned bundles unless signatures are required" do
      assert {:ok, verified} = Bundle.verify(bundle())
      assert verified.status == :unsigned
      assert verified.issuer == nil

      assert {:quarantine, quarantine} = Bundle.verify(bundle(), require_signature: true)
      assert quarantine.reason == :unsigned_bundle
    end

    test "quarantines digest mismatches before loading tampered content" do
      signed = Bundle.sign(bundle(), TestSigner, issuer: @issuer, issued_at: @issued_at)

      tampered =
        put_in(signed, ["patterns"], [
          %{
            "name" => "tampered",
            "regex" => "TAMPERED",
            "category" => "test",
            "severity" => "high"
          }
        ])

      assert {:quarantine, quarantine} =
               Bundle.verify(tampered, public_keys: %{@issuer => TestSigner.public_key_b64u()})

      assert quarantine.reason == :digest_mismatch
      assert quarantine.issuer == @issuer
    end

    test "quarantines invalid signatures" do
      signed = Bundle.sign(bundle(), TestSigner, issuer: @issuer, issued_at: @issued_at)
      bad_signature = Base.url_encode64(:binary.copy(<<0>>, 64), padding: false)
      tampered = put_in(signed, ["provenance", "signature"], bad_signature)

      assert {:quarantine, quarantine} =
               Bundle.verify(tampered, public_keys: %{@issuer => TestSigner.public_key_b64u()})

      assert quarantine.reason == :invalid_signature
      assert quarantine.issuer == @issuer
    end

    test "quarantines missing signature algorithms" do
      signed = Bundle.sign(bundle(), TestSigner, issuer: @issuer, issued_at: @issued_at)
      tampered = update_in(signed, ["provenance"], &Map.delete(&1, "algorithm"))

      assert {:quarantine, quarantine} =
               Bundle.verify(tampered, public_keys: %{@issuer => TestSigner.public_key_b64u()})

      assert quarantine.reason == :missing_algorithm
      assert quarantine.issuer == @issuer
    end

    test "quarantines unknown issuers" do
      signed = Bundle.sign(bundle(), TestSigner, issuer: @issuer, issued_at: @issued_at)

      assert {:quarantine, quarantine} = Bundle.verify(signed, public_keys: %{})
      assert quarantine.reason == :unknown_issuer
      assert quarantine.issuer == @issuer
    end
  end
end
