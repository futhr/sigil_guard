defmodule SigilGuard.TrustBundle.GoldenFixtureTest do
  use ExUnit.Case, async: true

  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.TrustBundle
  alias SigilGuard.TrustBundle.Schema
  alias SigilGuard.TrustBundleFixtureGenerator

  @fixtures Path.expand("../../fixtures/trust_bundle", __DIR__)
  @now ~U[2026-07-03 12:00:00.000Z]

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

    assert {:ok, %TrustBundle{digest: digest}} = TrustBundle.verify(genesis, now: @now)
    assert digest == expected["bundle_digest"]["genesis"]

    assert {:ok, %TrustBundle{digest: digest}} = TrustBundle.verify(successor, now: @now)
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

  defp document_digest(document) do
    {:ok, bytes} = JCS.encode(document)
    digest(bytes)
  end

  defp signatures(envelope), do: Map.new(envelope["signatures"], &{&1["keyid"], &1["sig"]})
  defp digest(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
end
