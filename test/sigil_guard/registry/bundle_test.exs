defmodule SigilGuard.Registry.BundleTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Registry.Bundle
  alias SigilGuard.TestSigner

  @issuer "did:sigil:registry"
  @issued_at "2026-06-30T12:00:00.000Z"
  @expires_at "2026-06-30T13:00:00.000Z"

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

    test "signs and verifies time-bound bundle provenance" do
      signed =
        Bundle.sign(bundle(), TestSigner,
          issuer: @issuer,
          issued_at: @issued_at,
          expires_at: @expires_at
        )

      assert {:ok, verified} =
               Bundle.verify(signed,
                 public_keys: %{@issuer => TestSigner.public_key_b64u()},
                 now: "2026-06-30T12:30:00Z",
                 max_age_seconds: 3_600
               )

      assert verified.status == :verified
      assert verified.provenance["expires_at"] == @expires_at
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

    test "quarantines expired signed bundles" do
      signed =
        Bundle.sign(bundle(), TestSigner,
          issuer: @issuer,
          issued_at: @issued_at,
          expires_at: @expires_at
        )

      assert {:quarantine, quarantine} =
               Bundle.verify(signed,
                 public_keys: %{@issuer => TestSigner.public_key_b64u()},
                 now: "2026-06-30T13:00:00Z"
               )

      assert quarantine.reason == :expired_bundle
      assert quarantine.issuer == @issuer
    end

    test "quarantines stale signed bundles when a maximum age is configured" do
      signed = Bundle.sign(bundle(), TestSigner, issuer: @issuer, issued_at: @issued_at)

      assert {:quarantine, quarantine} =
               Bundle.verify(signed,
                 public_keys: %{@issuer => TestSigner.public_key_b64u()},
                 now: "2026-06-30T12:10:01Z",
                 max_age_seconds: 600
               )

      assert quarantine.reason == :stale_bundle
      assert quarantine.issuer == @issuer
    end

    test "quarantines future issued-at timestamps beyond clock skew" do
      signed =
        Bundle.sign(bundle(), TestSigner,
          issuer: @issuer,
          issued_at: "2026-06-30T12:05:00Z"
        )

      assert {:quarantine, quarantine} =
               Bundle.verify(signed,
                 public_keys: %{@issuer => TestSigner.public_key_b64u()},
                 now: "2026-06-30T12:00:00Z",
                 clock_skew_seconds: 30
               )

      assert quarantine.reason == :future_issued_at
      assert quarantine.issuer == @issuer
    end

    test "quarantines missing issued-at timestamps when maximum age is configured" do
      signed = Bundle.sign(bundle(), TestSigner, issuer: @issuer, issued_at: @issued_at)
      tampered = update_in(signed, ["provenance"], &Map.delete(&1, "issued_at"))

      assert {:quarantine, quarantine} =
               Bundle.verify(tampered,
                 public_keys: %{@issuer => TestSigner.public_key_b64u()},
                 max_age_seconds: 600
               )

      assert quarantine.reason == :missing_issued_at
      assert quarantine.issuer == @issuer
    end

    test "quarantines invalid issued-at timestamps" do
      signed = Bundle.sign(bundle(), TestSigner, issuer: @issuer, issued_at: @issued_at)
      tampered = put_in(signed, ["provenance", "issued_at"], "not-a-timestamp")

      assert {:quarantine, quarantine} =
               Bundle.verify(tampered, public_keys: %{@issuer => TestSigner.public_key_b64u()})

      assert quarantine.reason == :invalid_issued_at
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
