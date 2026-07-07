defmodule SigilGuard.TelemetryTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Audit
  alias SigilGuard.Audit.Anchor
  alias SigilGuard.Audit.Anchor.Store
  alias SigilGuard.Audit.Anchor.Store.LocalFile
  alias SigilGuard.Audit.Checkpoint
  alias SigilGuard.Telemetry
  alias SigilGuard.TestSigner

  @secret_key :crypto.hash(:sha256, "audit anchor telemetry test key")
  @generated_at "2026-01-01T00:00:00.000Z"
  @anchored_at "2026-01-01T00:00:05.000Z"
  @issuer "did:web:anchor-telemetry.example"
  @expected_events [
    [:sigil_guard, :scan, :start],
    [:sigil_guard, :scan, :stop],
    [:sigil_guard, :scan, :exception],
    [:sigil_guard, :policy, :decision],
    [:sigil_guard, :boundary, :hook],
    [:sigil_guard, :boundary, :adaptive],
    [:sigil_guard, :runtime, :gate],
    [:sigil_guard, :mcp, :request],
    [:sigil_guard, :audit, :logged],
    [:sigil_guard, :audit, :anchor_store, :put, :start],
    [:sigil_guard, :audit, :anchor_store, :put, :stop],
    [:sigil_guard, :audit, :anchor_store, :put, :exception],
    [:sigil_guard, :audit, :anchor_store, :fetch, :start],
    [:sigil_guard, :audit, :anchor_store, :fetch, :stop],
    [:sigil_guard, :audit, :anchor_store, :fetch, :exception],
    [:sigil_guard, :audit, :anchor_store, :verify, :start],
    [:sigil_guard, :audit, :anchor_store, :verify, :stop],
    [:sigil_guard, :audit, :anchor_store, :verify, :exception],
    [:sigil_guard, :trust_bundle, :load, :start],
    [:sigil_guard, :trust_bundle, :load, :stop],
    [:sigil_guard, :trust_bundle, :load, :exception],
    [:sigil_guard, :trust_bundle, :verify, :start],
    [:sigil_guard, :trust_bundle, :verify, :stop],
    [:sigil_guard, :trust_bundle, :verify, :exception],
    [:sigil_guard, :trust_bundle, :quarantine],
    [:sigil_guard, :agent_trust, :card_verify, :start],
    [:sigil_guard, :agent_trust, :card_verify, :stop],
    [:sigil_guard, :agent_trust, :card_verify, :exception],
    [:sigil_guard, :agent_trust, :attest, :start],
    [:sigil_guard, :agent_trust, :attest, :stop],
    [:sigil_guard, :agent_trust, :attest, :exception],
    [:sigil_guard, :agent_trust, :verify, :start],
    [:sigil_guard, :agent_trust, :verify, :stop],
    [:sigil_guard, :agent_trust, :verify, :exception],
    [:sigil_guard, :agent_trust, :quarantine]
  ]

  describe "events/0" do
    test "lists known SigilGuard telemetry events" do
      assert Telemetry.events() == @expected_events
    end

    test "exposes only current SigilGuard event families" do
      assert Enum.uniq(Telemetry.events()) == Telemetry.events()
      assert Enum.all?(Telemetry.events(), &match?([:sigil_guard | _], &1))

      refute Enum.any?(Telemetry.events(), fn
               [:sigil_guard, :registry | _] -> true
               [:sigil_guard, :envelope | _] -> true
               _ -> false
             end)
    end
  end

  describe "otel_attributes/4" do
    test "maps runtime security metadata to the sigilguard.* namespace" do
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
            action_digest: "digest123",
            action_digest_error: :invalid_payload,
            hit_count: 1,
            indicator_ids: [:ignore_instructions],
            envelope_status: :invalid,
            envelope_reason: :invalid_signature,
            confirmation_status: :invalid,
            confirmation_reason: :digest_mismatch,
            confirmation_actor: "did:sigil:agent",
            confirmation_nonce_hash: "nonce-hash",
            release_status: :confirmed_sanitized,
            runtime_input_error: :invalid_action,
            scanner_error: :scanner_failed,
            content_hash: "abc123"
          },
          include_high_cardinality: true
        )

      # No attribute uses the retired sigil.* prefix; only sigilguard.* / url.full.
      assert Enum.all?(Map.keys(attributes), fn key ->
               String.starts_with?(key, "sigilguard.") or key == "url.full"
             end)

      assert attributes["sigilguard.event"] == "sigil_guard.runtime.gate"
      assert attributes["sigilguard.component"] == "runtime"
      assert attributes["sigilguard.operation"] == "gate"
      assert attributes["sigilguard.phase"] == "tool_request"
      assert attributes["sigilguard.actor.hash"] == "did:sigil:agent"
      assert attributes["sigilguard.identity.hash"] == "did:sigil:agent"
      assert attributes["sigilguard.verdict"] == "blocked"
      assert attributes["sigilguard.action.digest"] == "digest123"
      assert attributes["sigilguard.action.digest_error"] == "invalid_payload"
      assert attributes["sigilguard.hit_count"] == 1
      assert attributes["sigilguard.indicator_ids"] == ["ignore_instructions"]
      assert attributes["sigilguard.confirmation.status"] == "invalid"
      assert attributes["sigilguard.confirmation.reason"] == "digest_mismatch"
      assert attributes["sigilguard.confirmation.actor.hash"] == "did:sigil:agent"
      assert attributes["sigilguard.confirmation.nonce_hash"] == "nonce-hash"
      assert attributes["sigilguard.release.status"] == "confirmed_sanitized"
      assert attributes["sigilguard.runtime_input_error"] == "invalid_action"
      assert attributes["sigilguard.scanner.error"] == "scanner_failed"
      assert attributes["sigilguard.payload.digest"] == "abc123"

      # The legacy registry/envelope attributes are never emitted (SP.12).
      refute Map.has_key?(attributes, "sigil.envelope.status")
      refute Map.has_key?(attributes, "sigil.envelope.reason")
      refute Enum.any?(Map.keys(attributes), &String.contains?(&1, "envelope"))
    end

    test "drops high-cardinality attributes unless opted in" do
      metadata = %{
        verdict: :blocked,
        actor: "did:sigil:agent",
        identity: "did:sigil:agent",
        action_digest: "digest123",
        content_hash: "abc123",
        confirmation_actor: "did:sigil:agent",
        resource_uri: "file://x",
        hit_count: 3
      }

      bounded = Telemetry.otel_attributes([:sigil_guard, :runtime, :gate], %{}, metadata)

      # Bounded attributes are always present.
      assert bounded["sigilguard.verdict"] == "blocked"
      assert bounded["sigilguard.hit_count"] == 3

      # High-cardinality attributes are dropped by default.
      for key <- ~w(sigilguard.actor.hash sigilguard.identity.hash sigilguard.action.digest
                    sigilguard.payload.digest sigilguard.confirmation.actor.hash
                    sigilguard.resource.uri) do
        refute Map.has_key?(bounded, key)
      end

      opted_in =
        Telemetry.otel_attributes([:sigil_guard, :runtime, :gate], %{}, metadata,
          include_high_cardinality: true
        )

      assert opted_in["sigilguard.actor.hash"] == "did:sigil:agent"
      assert opted_in["sigilguard.payload.digest"] == "abc123"
      assert opted_in["sigilguard.resource.uri"] == "file://x"
    end

    test "uses official URL attribute naming and drops removed registry keys" do
      attributes =
        Telemetry.otel_attributes(
          [:sigil_guard, :registry, :fetch, :stop],
          %{duration: 10},
          %{
            url: "https://registry.example.test/patterns/bundle",
            endpoint: "patterns/bundle",
            count: 5,
            source: "remote"
          }
        )

      assert attributes["url.full"] == "https://registry.example.test/patterns/bundle"
      assert attributes["sigilguard.measurement.duration"] == 10
      # The legacy sigil.registry.* attributes are removed (SP.12).
      refute Enum.any?(Map.keys(attributes), &String.contains?(&1, "registry"))
      refute Enum.member?(Map.values(attributes), "patterns/bundle")
    end

    test "maps audit anchor-store metadata without raw paths" do
      attributes =
        Telemetry.otel_attributes(
          [:sigil_guard, :audit, :anchor_store, :put, :stop],
          %{duration: 10},
          %{
            anchor_store: "SigilGuard.Audit.Anchor.Store.LocalFile",
            anchor_digest: "abc123",
            anchor_storage: "local_file",
            anchor_uri_scheme: "file",
            outcome: :ok,
            error_reason: nil,
            uri: "file:///private/path/anchors.jsonl"
          },
          include_high_cardinality: true
        )

      assert attributes["sigilguard.event"] == "sigil_guard.audit.anchor_store.put.stop"
      assert attributes["sigilguard.component"] == "audit"
      assert attributes["sigilguard.operation"] == "anchor_store.put.stop"

      assert attributes["sigilguard.audit.anchor.store"] ==
               "SigilGuard.Audit.Anchor.Store.LocalFile"

      assert attributes["sigilguard.audit.anchor.digest"] == "abc123"
      assert attributes["sigilguard.audit.anchor.storage"] == "local_file"
      assert attributes["sigilguard.audit.anchor.uri_scheme"] == "file"
      assert attributes["sigilguard.outcome"] == "ok"
      refute Map.has_key?(attributes, "uri")
      refute Map.has_key?(attributes, "url.full")
    end

    test "drops nil, unknown, and unsupported attribute values" do
      attributes =
        Telemetry.otel_attributes(
          [:third_party, :event],
          %{duration: nil, unsupported: %{nested: true}},
          %{
            unknown: "ignored",
            phase: nil,
            indicator_ids: [:ignore_instructions, "direct", 42, true, %{nested: true}],
            repo_policy_rules: [%{not: "exportable"}]
          }
        )

      assert attributes["sigilguard.event"] == "third_party.event"
      assert attributes["sigilguard.component"] == "unknown"
      assert attributes["sigilguard.operation"] == "unknown"

      assert attributes["sigilguard.indicator_ids"] == [
               "ignore_instructions",
               "direct",
               42,
               true
             ]

      refute Map.has_key?(attributes, "unknown")
      refute Map.has_key?(attributes, "sigilguard.measurement.duration")
      refute Map.has_key?(attributes, "sigilguard.measurement.unsupported")
      refute Map.has_key?(attributes, "sigilguard.phase")
      refute Map.has_key?(attributes, "sigilguard.repo_policy.rules")
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
      assert attributes["sigilguard.action"] == "delete_database"
      assert attributes["sigilguard.risk_level"] == "high"
    end

    test "rejects duplicate handler IDs and reports missing detach targets" do
      handler_id = "sigil-otel-duplicate-test-#{System.unique_integer()}"

      assert :ok =
               Telemetry.attach_otel_forwarder(handler_id, fn _, _, _, _ -> :ok end,
                 events: [[:sigil_guard, :policy, :decision]]
               )

      on_exit(fn -> Telemetry.detach(handler_id) end)

      assert {:error, :already_exists} =
               Telemetry.attach_otel_forwarder(handler_id, fn _, _, _, _ -> :ok end,
                 events: [[:sigil_guard, :policy, :decision]]
               )

      assert {:error, :not_found} =
               Telemetry.detach("sigil-otel-missing-test-#{System.unique_integer()}")
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

  describe "anchor store telemetry" do
    test "emits audit-safe stop metadata for local anchor storage" do
      parent = self()
      ref = make_ref()
      handler_id = "sigil-anchor-store-test-#{System.unique_integer()}"

      :telemetry.attach_many(
        handler_id,
        [
          [:sigil_guard, :audit, :anchor_store, :put, :stop],
          [:sigil_guard, :audit, :anchor_store, :fetch, :stop],
          [:sigil_guard, :audit, :anchor_store, :verify, :stop]
        ],
        fn event, measurements, metadata, _ ->
          send(parent, {ref, event, measurements, metadata})
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      {checkpoint, anchor} = anchor_fixture()
      path = tmp_path()

      assert {:ok, receipt} = Store.put(LocalFile, anchor, path: path)
      assert {:ok, ^anchor} = Store.fetch(LocalFile, receipt)
      assert {:ok, verified} = Store.verify(LocalFile, receipt, checkpoint)

      assert verified.digest == receipt["anchor_digest"]

      assert_receive {^ref, [:sigil_guard, :audit, :anchor_store, :put, :stop], %{duration: _},
                      put_metadata}

      assert_receive {^ref, [:sigil_guard, :audit, :anchor_store, :fetch, :stop], %{duration: _},
                      fetch_metadata}

      assert_receive {^ref, [:sigil_guard, :audit, :anchor_store, :verify, :stop], %{duration: _},
                      verify_metadata}

      for metadata <- [put_metadata, fetch_metadata, verify_metadata] do
        assert metadata.anchor_store == "SigilGuard.Audit.Anchor.Store.LocalFile"
        assert metadata.anchor_digest == receipt["anchor_digest"]
        assert metadata.anchor_uri_scheme == "file"
        assert metadata.outcome == :ok
        refute Map.has_key?(metadata, :uri)
        refute Map.has_key?(metadata, :path)
        refute Map.has_key?(metadata, :record)
      end

      assert put_metadata.anchor_storage == "local_file"
    end

    test "emits error metadata for invalid stores" do
      parent = self()
      ref = make_ref()
      handler_id = "sigil-anchor-store-error-test-#{System.unique_integer()}"

      :telemetry.attach(
        handler_id,
        [:sigil_guard, :audit, :anchor_store, :put, :stop],
        fn event, measurements, metadata, _ ->
          send(parent, {ref, event, measurements, metadata})
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      assert {:error, :invalid_store} =
               Store.put(String, %{"kind" => "sigil_guard.audit.anchor"})

      assert_receive {^ref, [:sigil_guard, :audit, :anchor_store, :put, :stop], %{duration: _},
                      metadata}

      assert metadata.anchor_store == "String"
      assert metadata.outcome == :error
      assert metadata.error_reason == :invalid_store

      {_, anchor} = anchor_fixture()

      assert {:error, :worm_required} =
               Store.put(LocalFile, anchor, path: tmp_path(), require_worm: true)

      assert_receive {^ref, [:sigil_guard, :audit, :anchor_store, :put, :stop], %{duration: _},
                      worm_metadata}

      assert worm_metadata.anchor_store == "SigilGuard.Audit.Anchor.Store.LocalFile"
      assert worm_metadata.outcome == :error
      assert worm_metadata.error_reason == :worm_required
    end
  end

  defp anchor_fixture do
    events =
      1..3
      |> Enum.map(&Audit.new_event("test", "alice", "anchor-telemetry-#{&1}", "ok"))
      |> Audit.build_chain(@secret_key)

    {:ok, checkpoint} =
      Checkpoint.create(events,
        chain_id: "chain-a",
        generated_at: @generated_at
      )

    signed_checkpoint =
      Checkpoint.sign(checkpoint, TestSigner, issuer: @issuer, issued_at: @generated_at)

    anchor =
      Anchor.create(signed_checkpoint,
        anchored_at: @anchored_at,
        storage: :local_file,
        uri: "file://anchors.jsonl"
      )

    {signed_checkpoint, anchor}
  end

  defp tmp_path do
    root =
      System.tmp_dir!()
      |> Path.join("sigil_guard_anchor_telemetry_tests")
      |> Path.join("#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf(root) end)

    Path.join(root, "anchors.jsonl")
  end
end
