defmodule SigilGuard.TrustBundle.VerifyTest do
  use ExUnit.Case, async: true

  alias __MODULE__.BundleBackupSigner
  alias __MODULE__.BundleSigner
  alias __MODULE__.RootSigner
  alias __MODULE__.WitnessSigner
  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.TrustBundle
  alias SigilGuard.TrustBundle.Verify

  @now ~U[2026-07-03 12:00:00.000Z]
  @issued_at "2026-07-03T11:00:00.000Z"
  @expires_at "2026-07-03T13:00:00.000Z"
  @role_expires_at "2026-07-03T14:00:00.000Z"

  describe "verify/2" do
    test "verifies a bundle envelope and returns a trust-bundle snapshot" do
      document = bundle_document()
      envelope = envelope(document, [BundleSigner])

      assert {:ok, bundle} = Verify.verify(envelope, now: @now)
      assert bundle.bundle_id == "example-org-trust"
      assert bundle.sequence == 1
      assert bundle.root_version == 1
      assert bundle.document == document
      assert bundle.envelope == envelope
      assert bundle.digest == payload_digest(document)
      assert bundle.source == :none

      assert TrustBundle.verify(envelope, now: @now) == {:ok, bundle}
    end

    test "preserves load source metadata and dev provenance" do
      envelope = envelope(bundle_document(), [BundleSigner])
      encoded = Jason.encode!(envelope)

      assert {:ok, %TrustBundle{source: {:map, ^envelope}}} =
               TrustBundle.load({:map, envelope}, now: @now)

      assert {:ok, %TrustBundle{source: {:binary, ^encoded}}} =
               TrustBundle.load({:binary, encoded}, now: @now)

      assert {:ok, %TrustBundle{source: {:file, "/tmp/bundle.json"}}} =
               Verify.verify(envelope, now: @now, source: {:file, "/tmp/bundle.json"})

      assert {:ok, %TrustBundle{source: {:priv, :sigil_guard, "bundle.json"}}} =
               Verify.verify(envelope, now: @now, source: {:priv, :sigil_guard, "bundle.json"})

      assert {:ok, %TrustBundle{source: :none}} = Verify.verify(envelope, now: @now, source: :bad)

      dev_document = put_in(bundle_document(), ["provenance"], %{"issuer_class" => "dev"})
      dev_envelope = envelope(dev_document, [BundleSigner])

      assert {:ok, %TrustBundle{dev?: true, source: :dev}} =
               Verify.verify(dev_envelope, now: @now, source: :dev)
    end

    test "accepts atom-key envelopes and signatures" do
      envelope = envelope(bundle_document(), [BundleSigner])
      [signature] = envelope["signatures"]

      atom_envelope = %{
        payload: envelope["payload"],
        payloadType: envelope["payloadType"],
        signatures: [%{keyid: signature["keyid"], sig: signature["sig"]}]
      }

      assert {:ok, %TrustBundle{}} = Verify.verify(atom_envelope, now: @now)
    end

    test "enforces declared threshold only when requested" do
      document =
        bundle_document()
        |> put_in(["roles", "delegates", Access.at(0), "keyids"], [
          bundle_keyid(),
          bundle_backup_keyid()
        ])
        |> put_in(["roles", "delegates", Access.at(0), "threshold"], 2)
        |> put_in(["keys", bundle_backup_keyid()], key_descriptor(BundleBackupSigner))

      one_signature = envelope(document, [BundleSigner])
      two_signatures = envelope(document, [BundleSigner, BundleBackupSigner])

      assert {:ok, %TrustBundle{}} = Verify.verify(one_signature, now: @now)

      assert Verify.verify(one_signature, now: @now, enforce_declared_threshold: true) ==
               {:error, :threshold_not_met}

      assert {:ok, %TrustBundle{}} =
               Verify.verify(two_signatures, now: @now, enforce_declared_threshold: true)
    end

    test "rejects unknown, invalid, duplicate, and revoked signatures" do
      document = bundle_document()

      duplicate_keyid =
        document
        |> envelope([BundleSigner, {BundleBackupSigner, bundle_keyid()}])

      tampered_signature =
        document
        |> envelope([BundleSigner])
        |> put_in(
          ["signatures", Access.at(0), "sig"],
          Base.url_encode64(:binary.copy(<<0>>, 64), padding: false)
        )

      revoked =
        document
        |> Map.put("revocations", [
          %{"kind" => "key", "id" => bundle_keyid(), "revoked_at" => @issued_at}
        ])
        |> envelope([BundleSigner])

      assert Verify.verify(envelope(document, [WitnessSigner]), now: @now) ==
               {:error, :unknown_key_id}

      assert Verify.verify(tampered_signature, now: @now) == {:error, :invalid_signature}

      assert Verify.verify(
               put_in(
                 tampered_signature,
                 ["signatures", Access.at(0), "sig"],
                 Base.url_encode64("short", padding: false)
               ),
               now: @now
             ) ==
               {:error, :invalid_signature}

      assert Verify.verify(duplicate_keyid, now: @now) == {:error, :duplicate_keyid}
      assert Verify.verify(revoked, now: @now) == {:error, :revoked_key}
    end

    test "propagates schema unknown-role failures" do
      document = put_in(bundle_document(), ["roles", "delegates", Access.at(0), "name"], "other")

      assert Verify.verify(envelope(document, [BundleSigner]), now: @now) ==
               {:error, :unknown_role}
    end

    test "rejects expired roles and expired or future-dated documents" do
      assert bundle_document()
             |> put_in(
               ["roles", "delegates", Access.at(0), "expires_at"],
               "2026-07-03T11:30:00.000Z"
             )
             |> envelope([BundleSigner])
             |> Verify.verify(now: @now, max_skew_ms: 0) == {:error, :role_expired}

      assert bundle_document()
             |> Map.put("expires_at", "2026-07-03T11:30:00.000Z")
             |> envelope([BundleSigner])
             |> Verify.verify(now: @now, max_skew_ms: 0) == {:error, :bundle_expired}

      assert bundle_document()
             |> Map.put("issued_at", "2026-07-03T12:01:00.001Z")
             |> envelope([BundleSigner])
             |> Verify.verify(now: @now, max_skew_ms: 60_000) == {:error, :bundle_expired}
    end

    test "rejects malformed envelopes and payloads before role verification" do
      document = bundle_document()

      assert Verify.verify(%{}, now: @now) == {:error, :invalid_envelope}

      assert document
             |> envelope([BundleSigner])
             |> Map.put("payloadType", "application/json")
             |> Verify.verify(now: @now) == {:error, :invalid_payload_type}

      assert document
             |> envelope([BundleSigner])
             |> Map.put("payload", "*")
             |> Verify.verify(now: @now) == {:error, :invalid_base64}

      assert document
             |> envelope([BundleSigner])
             |> Map.put("signatures", ["bad"])
             |> Verify.verify(now: @now) == {:error, :invalid_envelope}

      assert %{
               "payload" => Base.url_encode64("[]", padding: false),
               "payloadType" => Envelope.payload_type(),
               "signatures" => [%{"keyid" => "k", "sig" => "s"}]
             }
             |> Verify.verify(now: @now) == {:error, :invalid_bundle_format}
    end

    test "rejects non-bundle documents and invalid options" do
      rotation =
        %{
          "profile" => "sigil_guard_root_rotation/v1",
          "bundle_id" => "example-org-trust",
          "root_version" => "2",
          "roles" => %{
            "root" => %{
              "keyids" => [root_keyid()],
              "threshold" => 1,
              "version" => "2",
              "expires_at" => @role_expires_at
            }
          },
          "keys" => %{root_keyid() => key_descriptor(RootSigner)},
          "rollback_floor" => "2",
          "issued_at" => @issued_at
        }

      assert Verify.verify(envelope(rotation, [RootSigner]), now: @now) ==
               {:error, :invalid_bundle_format}

      assert Verify.verify(envelope(bundle_document(), [BundleSigner]), now: "bad") ==
               {:error, :invalid_bundle_format}

      assert Verify.verify(envelope(bundle_document(), [BundleSigner]),
               now: @now,
               max_skew_ms: -1
             ) ==
               {:error, :invalid_bundle_format}
    end
  end

  defp bundle_document do
    %{
      "profile" => "sigil_guard_trust_bundle/v1",
      "bundle_id" => "example-org-trust",
      "sequence" => "1",
      "issued_at" => @issued_at,
      "expires_at" => @expires_at,
      "roles" => %{
        "root" => %{
          "keyids" => [root_keyid()],
          "threshold" => 1,
          "version" => "1",
          "expires_at" => "2027-07-03T12:00:00.000Z"
        },
        "delegates" => [
          %{
            "name" => "bundle",
            "keyids" => [bundle_keyid()],
            "threshold" => 1,
            "expires_at" => @role_expires_at
          }
        ]
      },
      "keys" => %{
        root_keyid() => key_descriptor(RootSigner),
        bundle_keyid() => key_descriptor(BundleSigner)
      },
      "rollback_floor" => "1"
    }
  end

  defp envelope(document, signers) do
    {:ok, payload} = JCS.encode(document)
    {:ok, envelope} = Envelope.sign_many(payload, signers)
    envelope
  end

  defp payload_digest(document) do
    {:ok, payload} = JCS.encode(document)
    Base.encode16(:crypto.hash(:sha256, payload), case: :lower)
  end

  defp key_descriptor(signer) do
    %{
      "alg" => "ed25519",
      "public_key" => Base.url_encode64(signer.public_key(), padding: false)
    }
  end

  defp root_keyid, do: Envelope.keyid(RootSigner.public_key())
  defp bundle_keyid, do: Envelope.keyid(BundleSigner.public_key())
  defp bundle_backup_keyid, do: Envelope.keyid(BundleBackupSigner.public_key())

  defmodule RootSigner do
    @behaviour SigilGuard.Signer
    @seed :crypto.hash(:sha256, "trust-bundle-root")

    @impl SigilGuard.Signer
    def sign(message), do: :crypto.sign(:eddsa, :none, message, [private_key(), :ed25519])

    @impl SigilGuard.Signer
    def public_key do
      {public_key, _} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      public_key
    end

    defp private_key do
      {_, private_key} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      private_key
    end
  end

  defmodule BundleSigner do
    @behaviour SigilGuard.Signer
    @seed :crypto.hash(:sha256, "trust-bundle-delegate")

    @impl SigilGuard.Signer
    def sign(message), do: :crypto.sign(:eddsa, :none, message, [private_key(), :ed25519])

    @impl SigilGuard.Signer
    def public_key do
      {public_key, _} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      public_key
    end

    defp private_key do
      {_, private_key} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      private_key
    end
  end

  defmodule BundleBackupSigner do
    @behaviour SigilGuard.Signer
    @seed :crypto.hash(:sha256, "trust-bundle-delegate-backup")

    @impl SigilGuard.Signer
    def sign(message), do: :crypto.sign(:eddsa, :none, message, [private_key(), :ed25519])

    @impl SigilGuard.Signer
    def public_key do
      {public_key, _} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      public_key
    end

    defp private_key do
      {_, private_key} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      private_key
    end
  end

  defmodule WitnessSigner do
    @behaviour SigilGuard.Signer
    @seed :crypto.hash(:sha256, "trust-bundle-witness")

    @impl SigilGuard.Signer
    def sign(message), do: :crypto.sign(:eddsa, :none, message, [private_key(), :ed25519])

    @impl SigilGuard.Signer
    def public_key do
      {public_key, _} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      public_key
    end

    defp private_key do
      {_, private_key} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      private_key
    end
  end
end
