defmodule SigilGuard.TrustBundle.NegativeMatrixTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias __MODULE__.BundleBackupSigner
  alias __MODULE__.BundleSigner
  alias __MODULE__.RootSigner
  alias __MODULE__.SuccessorSigner
  alias __MODULE__.WitnessSigner
  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.TrustBundle
  alias SigilGuard.TrustBundle.Cache

  @fixtures SigilGuard.FixturePath.path("trust_bundle")
  @now ~U[2026-07-03 12:00:00.000Z]
  @issued_at "2026-07-03T11:00:00.000Z"
  @expires_at "2026-07-03T13:00:00.000Z"
  @role_expires_at "2026-07-03T14:00:00.000Z"

  setup do
    Cache.clear()

    on_exit(fn -> Cache.clear() end)
  end

  test "matrix produces every trust-bundle error atom" do
    expected = MapSet.new(expected_error_atoms())

    produced =
      matrix_cases()
      |> Enum.map(fn {label, expected_reason, scenario} ->
        Cache.clear()

        assert scenario.() == {:error, expected_reason}, label
        expected_reason
      end)
      |> MapSet.new()

    assert produced == expected
  end

  defp expected_error_atoms do
    [
      :invalid_source,
      :invalid_envelope,
      :invalid_payload_type,
      :invalid_base64,
      :duplicate_keyid,
      :invalid_bundle_format,
      :unsupported_profile_version,
      :unknown_role,
      :unknown_key_id,
      :invalid_signature,
      :threshold_not_met,
      :bundle_expired,
      :role_expired,
      :revoked_key,
      :sequence_below_floor,
      :forked_root_chain,
      :rotation_below_threshold
    ]
  end

  defp matrix_cases do
    [
      {"invalid source", :invalid_source, fn -> TrustBundle.load(:none, now: @now) end},
      {"invalid envelope", :invalid_envelope, fn -> TrustBundle.verify(%{}, now: @now) end},
      {"invalid payload type", :invalid_payload_type,
       fn ->
         bundle_document()
         |> envelope([BundleSigner])
         |> Map.put("payloadType", "application/json")
         |> TrustBundle.verify(now: @now)
       end},
      {"invalid base64", :invalid_base64,
       fn ->
         bundle_document()
         |> envelope([BundleSigner])
         |> Map.put("payload", "*")
         |> TrustBundle.verify(now: @now)
       end},
      {"duplicate keyid", :duplicate_keyid,
       fn ->
         bundle_document()
         |> envelope([BundleSigner])
         |> Map.update!("signatures", fn [signature] -> [signature, signature] end)
         |> TrustBundle.verify(now: @now)
       end},
      {"invalid bundle format", :invalid_bundle_format,
       fn ->
         bundle_document()
         |> Map.delete("bundle_id")
         |> envelope([BundleSigner])
         |> TrustBundle.verify(now: @now)
       end},
      {"unsupported profile version", :unsupported_profile_version,
       fn ->
         bundle_document()
         |> Map.put("profile", "sigil_guard_trust_bundle/v2")
         |> envelope([BundleSigner])
         |> TrustBundle.verify(now: @now)
       end},
      {"unknown role", :unknown_role,
       fn ->
         bundle_document()
         |> put_in(["roles", "delegates", Access.at(0), "name"], "witness")
         |> envelope([BundleSigner])
         |> TrustBundle.verify(now: @now)
       end},
      {"unknown key id", :unknown_key_id,
       fn ->
         bundle_document()
         |> envelope([WitnessSigner])
         |> TrustBundle.verify(now: @now)
       end},
      {"invalid signature", :invalid_signature,
       fn ->
         bundle_document()
         |> envelope([BundleSigner])
         |> put_in(
           ["signatures", Access.at(0), "sig"],
           Base.url_encode64(:binary.copy(<<0>>, 64), padding: false)
         )
         |> TrustBundle.verify(now: @now)
       end},
      {"threshold not met", :threshold_not_met,
       fn ->
         bundle_document()
         |> add_backup_bundle_signer()
         |> envelope([BundleSigner])
         |> TrustBundle.verify(now: @now, enforce_declared_threshold: true)
       end},
      {"bundle expired", :bundle_expired,
       fn ->
         bundle_document()
         |> Map.put("expires_at", "2026-07-03T11:30:00.000Z")
         |> envelope([BundleSigner])
         |> TrustBundle.verify(now: @now, max_skew_ms: 0)
       end},
      {"role expired", :role_expired,
       fn ->
         bundle_document()
         |> put_in(
           ["roles", "delegates", Access.at(0), "expires_at"],
           "2026-07-03T11:30:00.000Z"
         )
         |> envelope([BundleSigner])
         |> TrustBundle.verify(now: @now, max_skew_ms: 0)
       end},
      {"revoked key", :revoked_key,
       fn ->
         bundle_document()
         |> Map.put("revocations", [
           %{"kind" => "key", "id" => bundle_keyid(), "revoked_at" => @issued_at}
         ])
         |> envelope([BundleSigner])
         |> TrustBundle.verify(now: @now)
       end},
      {"sequence below floor", :sequence_below_floor, &sequence_below_floor/0},
      {"forked root chain", :forked_root_chain, &forked_root_chain/0},
      {"rotation below threshold", :rotation_below_threshold, &rotation_below_threshold/0}
    ]
  end

  defp sequence_below_floor do
    genesis = read_json(["rotation", "genesis.json"])
    successor = read_json(["rotation", "successor.json"]) |> authorize_successor()

    assert {:ok, _} = TrustBundle.load({:map, genesis}, now: @now)
    assert {:ok, _} = TrustBundle.load({:map, successor}, now: @now)

    TrustBundle.load({:map, genesis}, now: @now)
  end

  defp forked_root_chain do
    successor = read_json(["rotation", "successor.json"]) |> authorize_successor()

    successor
    |> envelope_document()
    |> put_in(["rotation_chain"], [
      rotation(successor),
      read_json(["rotation", "forked-2.json"])
    ])
    |> signed_successor()
    |> TrustBundle.verify(now: @now, genesis_root: genesis_root())
  end

  defp rotation_below_threshold do
    successor = read_json(["rotation", "successor.json"]) |> authorize_successor()
    [rotation] = get_in(envelope_document(successor), ["rotation_chain"])

    successor
    |> envelope_document()
    |> put_in(["rotation_chain"], [
      put_in(rotation, ["signatures"], [old_root_signature(rotation)])
    ])
    |> signed_successor()
    |> TrustBundle.verify(now: @now, genesis_root: genesis_root())
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

  defp add_backup_bundle_signer(document) do
    document
    |> put_in(["roles", "delegates", Access.at(0), "keyids"], [
      bundle_keyid(),
      bundle_backup_keyid()
    ])
    |> put_in(["roles", "delegates", Access.at(0), "threshold"], 2)
    |> put_in(["keys", bundle_backup_keyid()], key_descriptor(BundleBackupSigner))
  end

  defp read_json(path) when is_list(path) do
    path
    |> then(&Path.join([@fixtures | &1]))
    |> File.read!()
    |> Jason.decode!()
  end

  defp envelope(document, signers) do
    {:ok, payload} = JCS.encode(document)
    {:ok, envelope} = Envelope.sign_many(payload, signers)
    envelope
  end

  defp signed_successor(document), do: envelope(document, [SuccessorSigner])

  defp envelope_document(envelope) do
    envelope
    |> Map.fetch!("payload")
    |> Base.url_decode64!(padding: false)
    |> Jason.decode!()
  end

  defp rotation(envelope) do
    envelope
    |> envelope_document()
    |> Map.fetch!("rotation_chain")
    |> List.first()
  end

  defp old_root_signature(rotation) do
    expected = read_json(["rotation", "expected.json"])
    old_root_keyid = expected["keyids"]["root"]
    Enum.find(rotation["signatures"], &(Map.fetch!(&1, "keyid") == old_root_keyid))
  end

  defp genesis_root do
    read_json(["rotation", "genesis.json"])
    |> envelope_document()
    |> root_pin()
  end

  defp root_pin(document) do
    root = get_in(document, ["roles", "root"])

    %{
      version: String.to_integer(root["version"]),
      threshold: root["threshold"],
      keyids: root["keyids"],
      keys: decoded_keys(document)
    }
  end

  defp decoded_keys(document) do
    Map.new(document["keys"], fn {keyid, %{"public_key" => encoded}} ->
      {:ok, public_key} = Base.url_decode64(encoded, padding: false)
      {keyid, public_key}
    end)
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
    @seed :crypto.hash(:sha256, "negative-matrix-root")

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
    @seed :crypto.hash(:sha256, "negative-matrix-bundle")

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
    @seed :crypto.hash(:sha256, "negative-matrix-bundle-backup")

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
    @seed :crypto.hash(:sha256, "negative-matrix-witness")

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

  defmodule SuccessorSigner do
    @behaviour SigilGuard.Signer
    @seed :binary.copy(<<0x99>>, 32)

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

  defp authorize_successor(envelope) do
    {:ok, signed} =
      Envelope.add_signature(envelope, SigilGuard.TrustBundleFixtureGenerator.NewRootSigner)

    signed
  end
end
