defmodule SigilGuard.TrustBundle.TelemetryTest do
  use ExUnit.Case, async: false

  alias SigilGuard.TrustBundle
  alias SigilGuard.TrustBundle.Cache
  alias SigilGuard.TrustBundle.Quarantine

  @fixtures Path.expand("../../fixtures/trust_bundle", __DIR__)
  @now ~U[2026-07-03 12:00:00.000Z]

  setup do
    Cache.clear()
    Quarantine.clear()

    on_exit(fn ->
      Cache.clear()
      Quarantine.clear()
    end)

    :ok
  end

  test "load and verify spans emit redacted success metadata without legacy registry events" do
    {handler_id, ref} = attach_events()
    on_exit(fn -> :telemetry.detach(handler_id) end)

    envelope = read_json(["minimal", "envelope.json"])

    assert {:ok, bundle} =
             TrustBundle.load({:map, envelope}, now: @now, cache: false, quarantine: false)

    assert bundle.bundle_id == "example-org-trust"

    assert_receive {^ref, [:sigil_guard, :trust_bundle, :load, :start], %{system_time: _},
                    load_start}

    assert_receive {^ref, [:sigil_guard, :trust_bundle, :verify, :start], %{system_time: _},
                    verify_start}

    assert_receive {^ref, [:sigil_guard, :trust_bundle, :verify, :stop], %{duration: _},
                    verify_stop}

    assert_receive {^ref, [:sigil_guard, :trust_bundle, :load, :stop], %{duration: _}, load_stop}

    assert span_metadata(load_start) == %{
             source: :map,
             bundle_id: nil,
             result: nil,
             error: nil,
             dev: false
           }

    assert span_metadata(load_stop) == %{
             source: :map,
             bundle_id: "example-org-trust",
             result: :ok,
             error: nil,
             dev: false
           }

    assert verify_start.bundle_id == "example-org-trust"
    assert verify_start.sequence == 1
    assert verify_start.root_version == 1
    assert verify_stop.result == :ok
    assert verify_stop.error == nil

    for metadata <- [load_start, load_stop, verify_start, verify_stop] do
      refute_sensitive_metadata(metadata)
    end

    refute_receive {^ref, [:sigil_guard, :registry, _, _], _, _}
  end

  test "verify failures emit error metadata and quarantine event without sensitive fields" do
    {handler_id, ref} = attach_events()
    on_exit(fn -> :telemetry.detach(handler_id) end)

    envelope = %{"payload" => "encoded"}

    assert TrustBundle.verify(envelope, now: @now) == {:error, :invalid_envelope}

    assert_receive {^ref, [:sigil_guard, :trust_bundle, :verify, :start], %{system_time: _},
                    verify_start}

    assert_receive {^ref, [:sigil_guard, :trust_bundle, :quarantine], %{count: 1}, quarantine}

    assert_receive {^ref, [:sigil_guard, :trust_bundle, :verify, :stop], %{duration: _},
                    verify_stop}

    assert span_metadata(verify_start) == %{
             bundle_id: nil,
             sequence: nil,
             root_version: nil,
             result: nil,
             error: nil
           }

    assert verify_stop.result == :error
    assert verify_stop.error == :invalid_envelope
    assert quarantine.reason == :invalid_envelope
    assert quarantine.bundle_id == nil
    assert quarantine.dev == false

    for metadata <- [verify_start, verify_stop, quarantine] do
      refute_sensitive_metadata(metadata)
    end
  end

  test "dev bundle load span carries dev metadata" do
    {handler_id, ref} = attach_events()
    on_exit(fn -> :telemetry.detach(handler_id) end)

    seed = :binary.copy(<<0x44>>, 32)

    assert {:ok, %TrustBundle{dev?: true}} =
             TrustBundle.dev_bundle(seed: seed, now: @now, cache: false)

    assert_receive {^ref, [:sigil_guard, :trust_bundle, :load, :start], %{system_time: _}, _}
    assert_receive {^ref, [:sigil_guard, :trust_bundle, :verify, :start], %{system_time: _}, _}

    assert_receive {^ref, [:sigil_guard, :trust_bundle, :verify, :stop], %{duration: _},
                    verify_stop}

    assert_receive {^ref, [:sigil_guard, :trust_bundle, :load, :stop], %{duration: _}, load_stop}

    assert verify_stop.result == :ok
    assert load_stop.dev == true
    assert load_stop.source == :dev
    assert load_stop.bundle_id == "sigilguard-dev"
  end

  test "telemetry event registry includes trust-bundle events" do
    assert [:sigil_guard, :trust_bundle, :load, :start] in SigilGuard.Telemetry.events()
    assert [:sigil_guard, :trust_bundle, :load, :stop] in SigilGuard.Telemetry.events()
    assert [:sigil_guard, :trust_bundle, :verify, :start] in SigilGuard.Telemetry.events()
    assert [:sigil_guard, :trust_bundle, :verify, :stop] in SigilGuard.Telemetry.events()
    assert [:sigil_guard, :trust_bundle, :quarantine] in SigilGuard.Telemetry.events()
  end

  defp attach_events do
    parent = self()
    ref = make_ref()
    handler_id = "sigil-trust-bundle-telemetry-test-#{System.unique_integer()}"

    :telemetry.attach_many(
      handler_id,
      SigilGuard.Telemetry.events(),
      fn event, measurements, metadata, _ ->
        send(parent, {ref, event, measurements, metadata})
      end,
      nil
    )

    {handler_id, ref}
  end

  defp read_json(path) do
    path
    |> then(&Path.join([@fixtures | &1]))
    |> File.read!()
    |> Jason.decode!()
  end

  defp refute_sensitive_metadata(metadata) do
    refute Map.has_key?(metadata, :document)
    refute Map.has_key?(metadata, :envelope)
    refute Map.has_key?(metadata, :payload)
    refute Map.has_key?(metadata, :signatures)
    refute Map.has_key?(metadata, :keys)
    refute Map.has_key?(metadata, :patterns)
    refute Map.has_key?(metadata, :policies)
    refute Map.has_key?(metadata, :tools)
    refute Map.has_key?(metadata, :identity_issuers)
  end

  defp span_metadata(metadata), do: Map.delete(metadata, :telemetry_span_context)
end
