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

  describe "events/0" do
    test "lists known SigilGuard telemetry events" do
      assert [:sigil_guard, :runtime, :gate] in Telemetry.events()
      assert [:sigil_guard, :mcp, :request] in Telemetry.events()
      assert [:sigil_guard, :scan, :stop] in Telemetry.events()
      assert [:sigil_guard, :audit, :logged] in Telemetry.events()
      assert [:sigil_guard, :audit, :anchor_store, :put, :stop] in Telemetry.events()
      assert [:sigil_guard, :audit, :anchor_store, :fetch, :stop] in Telemetry.events()
      assert [:sigil_guard, :audit, :anchor_store, :verify, :stop] in Telemetry.events()
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
          }
        )

      assert attributes["sigil.event"] == "sigil_guard.audit.anchor_store.put.stop"
      assert attributes["sigil.component"] == "audit"
      assert attributes["sigil.operation"] == "anchor_store.put.stop"
      assert attributes["sigil.audit.anchor.store"] == "SigilGuard.Audit.Anchor.Store.LocalFile"
      assert attributes["sigil.audit.anchor.digest"] == "abc123"
      assert attributes["sigil.audit.anchor.storage"] == "local_file"
      assert attributes["sigil.audit.anchor.uri_scheme"] == "file"
      assert attributes["sigil.outcome"] == "ok"
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

      assert attributes["sigil.event"] == "third_party.event"
      assert attributes["sigil.component"] == "unknown"
      assert attributes["sigil.operation"] == "unknown"

      assert attributes["sigil.security.indicator_ids"] == [
               "ignore_instructions",
               "direct",
               42,
               true
             ]

      refute Map.has_key?(attributes, "unknown")
      refute Map.has_key?(attributes, "sigil.measurement.duration")
      refute Map.has_key?(attributes, "sigil.measurement.unsupported")
      refute Map.has_key?(attributes, "sigil.security.phase")
      refute Map.has_key?(attributes, "sigil.repo_policy.rules")
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
