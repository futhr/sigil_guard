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

    test "normalizes atom and numeric keys in canonical bytes" do
      raw = %{
        generated_at: "2026-06-30T12:00:00Z",
        patterns: [
          %{
            1 => :numeric_key,
            name: "registry_pat",
            regex: "REG_[0-9]+",
            category: "test",
            severity: "low"
          }
        ]
      }

      decoded =
        raw
        |> Bundle.canonical_bytes()
        |> Jason.decode!()

      assert decoded["patterns"] == [
               %{
                 "1" => "numeric_key",
                 "category" => "test",
                 "name" => "registry_pat",
                 "regex" => "REG_[0-9]+",
                 "severity" => "low"
               }
             ]
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

    test "defaults provenance issued_at and omits nil expiry" do
      signed = Bundle.sign(bundle(), TestSigner, issuer: @issuer)

      assert is_binary(signed["provenance"]["issued_at"])
      assert {:ok, _, _} = DateTime.from_iso8601(signed["provenance"]["issued_at"])
      refute Map.has_key?(signed["provenance"], "expires_at")
    end

    test "verifies signed bundles with standard base64 public keys and signatures" do
      signed = Bundle.sign(bundle(), TestSigner, issuer: @issuer, issued_at: @issued_at)

      signature =
        signed["provenance"]["signature"]
        |> Base.url_decode64!(padding: false)
        |> Base.encode64()

      reencoded = put_in(signed, ["provenance", "signature"], signature)
      public_key = Base.encode64(TestSigner.public_key())

      assert {:ok, verified} = Bundle.verify(reencoded, public_key_b64u: public_key)
      assert verified.status == :verified
    end

    test "verifies atom-keyed provenance metadata" do
      signed = Bundle.sign(bundle(), TestSigner, issuer: @issuer, issued_at: @issued_at)

      atom_provenance =
        Map.new(signed["provenance"], fn {key, value} -> {String.to_existing_atom(key), value} end)

      atom_signed =
        signed
        |> Map.delete("provenance")
        |> Map.put(:provenance, atom_provenance)

      assert {:ok, verified} =
               Bundle.verify(atom_signed, public_keys: %{@issuer => TestSigner.public_key_b64u()})

      assert verified.status == :verified
      assert verified.provenance == atom_provenance
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

    test "quarantines invalid bundles and provenance shapes" do
      assert {:quarantine, quarantine} = Bundle.verify(:bad)
      assert quarantine.reason == :invalid_bundle
      assert quarantine.digest == nil

      assert {:quarantine, quarantine} =
               bundle()
               |> Map.put("provenance", "bad")
               |> Bundle.verify()

      assert quarantine.reason == :invalid_provenance
      assert is_binary(quarantine.digest)
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

    test "quarantines missing provenance fields and unsupported algorithms" do
      signed = Bundle.sign(bundle(), TestSigner, issuer: @issuer, issued_at: @issued_at)

      for {field, reason} <- [
            {"issuer", :missing_issuer},
            {"digest", :missing_digest},
            {"signature", :missing_signature}
          ] do
        tampered = update_in(signed, ["provenance"], &Map.delete(&1, field))
        assert {:quarantine, quarantine} = Bundle.verify(tampered)
        assert quarantine.reason == reason
      end

      unsupported = put_in(signed, ["provenance", "algorithm"], "RSA")
      assert {:quarantine, quarantine} = Bundle.verify(unsupported)
      assert quarantine.reason == :unsupported_algorithm
    end

    test "quarantines invalid verification time options and timestamps" do
      signed = Bundle.sign(bundle(), TestSigner, issuer: @issuer, issued_at: @issued_at)

      assert {:quarantine, quarantine} =
               Bundle.verify(signed,
                 public_key_b64u: TestSigner.public_key_b64u(),
                 max_age_seconds: -1
               )

      assert quarantine.reason == :invalid_max_age

      assert {:quarantine, quarantine} =
               Bundle.verify(signed,
                 public_key_b64u: TestSigner.public_key_b64u(),
                 clock_skew_seconds: -1
               )

      assert quarantine.reason == :invalid_clock_skew

      assert {:quarantine, quarantine} =
               Bundle.verify(signed,
                 public_key_b64u: TestSigner.public_key_b64u(),
                 now: :bad
               )

      assert quarantine.reason == :invalid_now

      invalid_expires = put_in(signed, ["provenance", "expires_at"], :bad)

      assert {:quarantine, quarantine} =
               Bundle.verify(invalid_expires, public_key_b64u: TestSigner.public_key_b64u())

      assert quarantine.reason == :invalid_expires_at
    end

    test "accepts missing issued-at when age checks are disabled" do
      signed = Bundle.sign(bundle(), TestSigner, issuer: @issuer, issued_at: @issued_at)
      no_issued_at = update_in(signed, ["provenance"], &Map.delete(&1, "issued_at"))

      assert {:ok, verified} =
               Bundle.verify(no_issued_at, public_key_b64u: TestSigner.public_key_b64u())

      assert verified.status == :verified
    end

    test "quarantines malformed public keys and signatures" do
      signed = Bundle.sign(bundle(), TestSigner, issuer: @issuer, issued_at: @issued_at)
      short_public_key = Base.url_encode64("short", padding: false)
      short_signature = Base.url_encode64("short", padding: false)

      assert {:quarantine, quarantine} = Bundle.verify(signed, public_key_b64u: "not base64!")
      assert quarantine.reason == :invalid_base64

      assert {:quarantine, quarantine} = Bundle.verify(signed, public_key_b64u: short_public_key)
      assert quarantine.reason == :invalid_key

      short_sig_bundle = put_in(signed, ["provenance", "signature"], short_signature)

      assert {:quarantine, quarantine} =
               Bundle.verify(short_sig_bundle, public_key_b64u: TestSigner.public_key_b64u())

      assert quarantine.reason == :invalid_signature

      bad_sig_bundle = put_in(signed, ["provenance", "signature"], "not base64!")

      assert {:quarantine, quarantine} =
               Bundle.verify(bad_sig_bundle, public_key_b64u: TestSigner.public_key_b64u())

      assert quarantine.reason == :invalid_base64
    end

    test "treats invalid Ed25519 public-key points as signature failures" do
      signed = Bundle.sign(bundle(), TestSigner, issuer: @issuer, issued_at: @issued_at)
      invalid_curve_point = Base.url_encode64(:binary.copy(<<0>>, 32), padding: false)

      assert {:quarantine, quarantine} =
               Bundle.verify(signed, public_key_b64u: invalid_curve_point)

      assert quarantine.reason == :invalid_signature
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
