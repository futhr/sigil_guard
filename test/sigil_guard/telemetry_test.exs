defmodule SigilGuard.TelemetryTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Telemetry

  describe "events/0" do
    test "lists known SigilGuard telemetry events" do
      assert [:sigil_guard, :runtime, :gate] in Telemetry.events()
      assert [:sigil_guard, :mcp, :request] in Telemetry.events()
      assert [:sigil_guard, :scan, :stop] in Telemetry.events()
      assert [:sigil_guard, :audit, :logged] in Telemetry.events()
    end
  end

  describe "otel_attributes/3" do
    test "maps runtime security metadata to OTel-style attributes" do
      attributes =
        Telemetry.otel_attributes(
          [:sigil_guard, :runtime, :gate],
          %{system_time: 123},
          %{
            phase: :tool_request,
            actor: "did:sigil:agent",
            identity: "did:sigil:agent",
            origin: :model,
            sink: :external,
            tool: "send_webhook",
            trust_zone: :semi_trusted,
            trust_level: :high,
            risk_level: :high,
            verdict: :blocked,
            action: :block,
            hit_count: 1,
            indicator_ids: [:ignore_instructions],
            envelope_status: :invalid,
            envelope_reason: :invalid_signature,
            confirmation_status: :invalid,
            confirmation_reason: :digest_mismatch,
            confirmation_actor: "did:sigil:agent",
            confirmation_nonce_hash: "nonce-hash",
            release_status: :confirmed_sanitized,
            content_hash: "abc123"
          }
        )

      assert attributes["sigil.event"] == "sigil_guard.runtime.gate"
      assert attributes["sigil.component"] == "runtime"
      assert attributes["sigil.operation"] == "gate"
      assert attributes["sigil.security.phase"] == "tool_request"
      assert attributes["sigil.actor"] == "did:sigil:agent"
      assert attributes["sigil.identity"] == "did:sigil:agent"
      assert attributes["sigil.security.verdict"] == "blocked"
      assert attributes["sigil.security.hit_count"] == 1
      assert attributes["sigil.security.indicator_ids"] == ["ignore_instructions"]
      assert attributes["sigil.envelope.status"] == "invalid"
      assert attributes["sigil.envelope.reason"] == "invalid_signature"
      assert attributes["sigil.confirmation.status"] == "invalid"
      assert attributes["sigil.confirmation.reason"] == "digest_mismatch"
      assert attributes["sigil.confirmation.actor"] == "did:sigil:agent"
      assert attributes["sigil.confirmation.nonce_hash"] == "nonce-hash"
      assert attributes["sigil.release.status"] == "confirmed_sanitized"
      assert attributes["sigil.security.content_hash"] == "abc123"
      refute Map.has_key?(attributes, "match")
    end

    test "uses official URL attribute naming for registry URLs" do
      attributes =
        Telemetry.otel_attributes(
          [:sigil_guard, :registry, :fetch, :stop],
          %{duration: 10},
          %{url: "https://registry.example.test/patterns/bundle", endpoint: "patterns/bundle"}
        )

      assert attributes["url.full"] == "https://registry.example.test/patterns/bundle"
      assert attributes["sigil.registry.endpoint"] == "patterns/bundle"
      assert attributes["sigil.measurement.duration"] == 10
    end
  end

  describe "attach_otel_forwarder/3" do
    test "forwards event, metadata, and OTel-style attributes" do
      parent = self()
      handler_id = "sigil-otel-test-#{System.unique_integer()}"

      assert :ok =
               Telemetry.attach_otel_forwarder(
                 handler_id,
                 fn event, measurements, metadata, attributes ->
                   send(parent, {event, measurements, metadata, attributes})
                 end,
                 events: [[:sigil_guard, :policy, :decision]]
               )

      on_exit(fn -> Telemetry.detach(handler_id) end)

      Telemetry.emit(
        [:sigil_guard, :policy, :decision],
        %{system_time: 123},
        %{action: "delete_database", risk_level: :high, trust_level: :low}
      )

      assert_receive {[:sigil_guard, :policy, :decision], %{system_time: 123}, metadata,
                      attributes}

      assert metadata.action == "delete_database"
      assert attributes["sigil.security.action"] == "delete_database"
      assert attributes["sigil.security.risk_level"] == "high"
    end
  end

  describe "scan telemetry" do
    test "includes scanner pipeline metadata" do
      parent = self()
      ref = make_ref()
      handler_id = "sigil-scan-test-#{System.unique_integer()}"

      :telemetry.attach(
        handler_id,
        [:sigil_guard, :scan, :stop],
        fn event, measurements, metadata, _ ->
          send(parent, {ref, event, measurements, metadata})
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      SigilGuard.scan("safe text")

      assert_receive {^ref, [:sigil_guard, :scan, :stop], %{duration: _}, metadata}
      assert metadata.pipeline == :staged
      assert metadata.scanner_validate
      assert metadata.patterns_checked > 0
      assert metadata.hit_count == 0
    end
  end
end
