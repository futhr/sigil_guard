defmodule SigilGuard.TrustBundle.GoldenFixtureTest do
  use ExUnit.Case, async: false

  alias __MODULE__.SuccessorSigner
  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.TrustBundle
  alias SigilGuard.TrustBundle.Cache
  alias SigilGuard.TrustBundle.Schema
  alias SigilGuard.TrustBundleFixtureGenerator

  @fixtures Path.expand("../../fixtures/trust_bundle", __DIR__)
  @now ~U[2026-07-03 12:00:00.000Z]

  setup do
    Cache.clear()

    on_exit(fn -> Cache.clear() end)
  end

  test "committed trust-bundle fixtures regenerate byte-identically" do
    for {dir, files} <- TrustBundleFixtureGenerator.generate(),
        {name, bytes} <- files do
      assert File.read!(Path.join([@fixtures, dir, name])) == bytes
    end
  end

  test "minimal and multisig fixtures verify and assert stored digests" do
    for name <- ~w(minimal multisig) do
      bundle_json = File.read!(Path.join([@fixtures, name, "bundle.json"]))
      envelope = read_json([name, "envelope.json"])
      expected = read_json([name, "expected.json"])

      assert {:ok, ^bundle_json} = JCS.encode(read_json([name, "bundle.json"]))
      assert digest(bundle_json) == expected["bundle_digest"]
      assert digest(Envelope.pae(Envelope.payload_type(), bundle_json)) == expected["pae_sha256"]
      assert signatures(envelope) == expected["signatures"]

      assert {:ok, %TrustBundle{digest: digest}} = TrustBundle.verify(envelope, now: @now)
      assert digest == expected["bundle_digest"]
    end
  end

  test "rotation fixtures validate current schema and record recomputed digests" do
    expected = read_json(["rotation", "expected.json"])

    genesis = read_json(["rotation", "genesis.json"])
    successor = read_json(["rotation", "successor.json"])
    genesis_root = root_pin(envelope_document(genesis))

    assert {:ok, %TrustBundle{digest: digest}} = TrustBundle.verify(genesis, now: @now)
    assert digest == expected["bundle_digest"]["genesis"]

    assert {:ok, %TrustBundle{digest: digest, root_version: 2}} =
             TrustBundle.verify(successor, now: @now, genesis_root: genesis_root)

    assert digest == expected["bundle_digest"]["successor"]

    for name <- ~w(rotation-2 forked-2) do
      envelope = read_json(["rotation", "#{name}.json"])
      document = envelope_document(envelope)

      assert Schema.validate(document) == {:ok, :rotation, document}
      assert TrustBundle.verify(envelope, now: @now) == {:error, :invalid_bundle_format}
      assert document_digest(document) == expected["bundle_digest"][name]

      assert digest(Envelope.pae(Envelope.payload_type(), envelope_payload(envelope))) ==
               expected["pae_sha256"][name]

      assert signatures(envelope) == expected["signatures"][name]
    end
  end

  test "rotation chain rejects missing quorums, gaps, and terminal mismatches" do
    genesis = read_json(["rotation", "genesis.json"])
    successor = read_json(["rotation", "successor.json"])
    genesis_root = root_pin(envelope_document(genesis))
    [rotation] = get_in(envelope_document(successor), ["rotation_chain"])

    old_only =
      successor
      |> envelope_document()
      |> put_in(["rotation_chain"], [
        put_in(rotation, ["signatures"], [old_root_signature(rotation)])
      ])
      |> signed_successor()

    assert TrustBundle.verify(old_only, now: @now, genesis_root: genesis_root) ==
             {:error, :rotation_below_threshold}

    gapped =
      successor
      |> envelope_document()
      |> put_in(["rotation_chain", Access.at(0), "payload"], gapped_rotation_payload(rotation))
      |> signed_successor()

    assert TrustBundle.verify(gapped, now: @now, genesis_root: genesis_root) ==
             {:error, :invalid_bundle_format}

    terminal_mismatch =
      successor
      |> envelope_document()
      |> put_in(["roles", "root", "threshold"], 2)
      |> signed_successor()

    assert TrustBundle.verify(terminal_mismatch, now: @now, genesis_root: genesis_root) ==
             {:error, :invalid_bundle_format}
  end

  test "cached genesis pin verifies successor rotation chain" do
    genesis = read_json(["rotation", "genesis.json"])
    successor = read_json(["rotation", "successor.json"])

    assert {:ok, %TrustBundle{root_version: 1}} = TrustBundle.load({:map, genesis}, now: @now)

    assert {:ok, %TrustBundle{root_version: 2, sequence: 2}} =
             TrustBundle.load({:map, successor}, now: @now)
  end

  test "rotation chain rejects forked roots in-chain and against cached digests" do
    genesis = read_json(["rotation", "genesis.json"])
    successor = read_json(["rotation", "successor.json"])
    forked_rotation = read_json(["rotation", "forked-2.json"])
    genesis_root = root_pin(envelope_document(genesis))

    in_chain_fork =
      successor
      |> envelope_document()
      |> put_in(["rotation_chain"], [rotation(successor), forked_rotation])
      |> signed_successor()

    assert TrustBundle.verify(in_chain_fork, now: @now, genesis_root: genesis_root) ==
             {:error, :forked_root_chain}

    assert {:ok, %TrustBundle{root_version: 1}} = TrustBundle.load({:map, genesis}, now: @now)
    assert {:ok, %TrustBundle{root_version: 2}} = TrustBundle.load({:map, successor}, now: @now)

    cached_fork =
      successor
      |> envelope_document()
      |> put_in(["rotation_chain"], [forked_rotation])
      |> signed_successor()

    assert TrustBundle.verify(cached_fork, now: @now) == {:error, :forked_root_chain}
  end

  test "pre-rotation bundles replay below the accepted floor" do
    genesis = read_json(["rotation", "genesis.json"])
    successor = read_json(["rotation", "successor.json"])

    assert {:ok, %TrustBundle{sequence: 1}} = TrustBundle.load({:map, genesis}, now: @now)

    assert {:ok, %TrustBundle{sequence: 2, root_version: 2}} =
             TrustBundle.load({:map, successor}, now: @now)

    assert TrustBundle.load({:map, genesis}, now: @now) == {:error, :sequence_below_floor}
  end

  defp read_json(path) when is_list(path) do
    path
    |> then(&Path.join([@fixtures | &1]))
    |> File.read!()
    |> Jason.decode!()
  end

  defp envelope_document(envelope) do
    envelope
    |> envelope_payload()
    |> Jason.decode!()
  end

  defp envelope_payload(envelope) do
    envelope
    |> Map.fetch!("payload")
    |> Base.url_decode64!(padding: false)
  end

  defp encoded_payload(document) do
    {:ok, bytes} = JCS.encode(document)
    Base.url_encode64(bytes, padding: false)
  end

  defp signed_successor(document) do
    {:ok, payload} = JCS.encode(document)
    {:ok, envelope} = Envelope.sign_many(payload, [SuccessorSigner])
    envelope
  end

  defp rotation(envelope) do
    envelope
    |> envelope_document()
    |> Map.fetch!("rotation_chain")
    |> List.first()
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

  defp old_root_signature(rotation) do
    expected = read_json(["rotation", "expected.json"])
    old_root_keyid = expected["keyids"]["root"]
    Enum.find(rotation["signatures"], &(Map.fetch!(&1, "keyid") == old_root_keyid))
  end

  defp gapped_rotation_payload(rotation) do
    rotation
    |> envelope_document()
    |> Map.put("root_version", "3")
    |> put_in(["roles", "root", "version"], "3")
    |> encoded_payload()
  end

  defp document_digest(document) do
    {:ok, bytes} = JCS.encode(document)
    digest(bytes)
  end

  defp signatures(envelope), do: Map.new(envelope["signatures"], &{&1["keyid"], &1["sig"]})
  defp digest(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

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
end
