defmodule SigilGuard.Audit.CloudEventsTest do
  use ExUnit.Case, async: true

  alias SigilGuard.Audit
  alias SigilGuard.Audit.CloudEvents

  @field_hash_key :crypto.hash(:sha256, "cloudevents field hash key")
  @chain_key :crypto.hash(:sha256, "cloudevents chain key")
  @trace_id "0af7651916cd43dd8448eb211c80319c"
  @span_id "b7ad6b7169203331"

  setup do
    event =
      %Audit{
        id: "00000000000000000000000000000001",
        type: "runtime.gate",
        actor: "did:web:alice",
        action: "repo_file_write",
        result: "block",
        timestamp: "2026-07-02T12:00:00.000Z",
        metadata: %{
          "decision" => %{"matched_rules" => ["repo.write.block"], "verdict" => "block"},
          "decision_id" => "9f8e7d6c5b4a39281706f5e4d3c2b1a0",
          "evidence" => [%{"kind" => "checkpoint", "ref" => "abc"}],
          "payload_digest" => "d6c2b1a0",
          "trace_id" => @trace_id,
          "span_id" => @span_id,
          "raw_prompt" => "exfiltrate the API key",
          "host_custom" => "unclassified"
        }
      }
      |> Audit.classify(field_hash_key: @field_hash_key)
      |> Audit.sign_event(@chain_key)

    %{event: event}
  end

  describe "project/2" do
    test "emits the CloudEvents 1.0 decision envelope shape", ctx do
      ce = CloudEvents.project(ctx.event, source: "urn:sigilguard:prod-agent-runtime-1")

      assert ce["specversion"] == "1.0"
      assert ce["type"] == "io.sigilguard.decision.v1"
      assert ce["source"] == "urn:sigilguard:prod-agent-runtime-1"
      assert ce["id"] == ctx.event.id
      assert ce["time"] == "2026-07-02T12:00:00.000Z"
      assert ce["datacontenttype"] == "application/json"
      assert ce["traceparent"] == "00-#{@trace_id}-#{@span_id}-01"

      assert ce["data"] == %{
               "id" => ctx.event.id,
               "type" => "runtime.gate",
               "actor" => ctx.event.actor,
               "action" => "repo_file_write",
               "result" => "block",
               "timestamp" => "2026-07-02T12:00:00.000Z",
               "prev_hmac" => nil,
               "hmac" => ctx.event.hmac,
               "metadata" => %{
                 "decision" => %{
                   "matched_rules" => ["repo.write.block"],
                   "verdict" => "block"
                 },
                 "decision_id" => "9f8e7d6c5b4a39281706f5e4d3c2b1a0",
                 "evidence" => [%{"kind" => "checkpoint", "ref" => "abc"}],
                 "payload_digest" => "d6c2b1a0"
               }
             }
    end

    test "carries the privacy-classified actor, not a raw identifier", ctx do
      ce = CloudEvents.project(ctx.event)

      assert String.starts_with?(ce["data"]["actor"], "fh1:")
      refute ce["data"]["actor"] == "did:web:alice"
    end

    test "the envelope contains no raw content or unclassified host metadata", ctx do
      json = Jason.encode!(CloudEvents.project(ctx.event))

      refute json =~ "exfiltrate the API key"
      refute json =~ "unclassified"
      refute json =~ "did:web:alice"
    end

    test "omits non-reserved and trace metadata keys from data", ctx do
      data_metadata = CloudEvents.project(ctx.event)["data"]["metadata"]

      refute Map.has_key?(data_metadata, "raw_prompt")
      refute Map.has_key?(data_metadata, "host_custom")
      # trace_id/span_id are projected as traceparent, never duplicated in data.
      refute Map.has_key?(data_metadata, "trace_id")
      refute Map.has_key?(data_metadata, "span_id")
    end

    test "defaults the source and omits traceparent without trace context", ctx do
      event = %{ctx.event | metadata: %{"decision_id" => "x"}}
      ce = CloudEvents.project(event)

      assert ce["source"] == "urn:sigilguard"
      refute Map.has_key?(ce, "traceparent")
      assert ce["data"]["metadata"] == %{"decision_id" => "x"}
    end

    test "omits traceparent when only one of trace_id/span_id is present", ctx do
      trace_only = %{ctx.event | metadata: %{"trace_id" => @trace_id}}
      span_only = %{ctx.event | metadata: %{"span_id" => @span_id}}

      refute Map.has_key?(CloudEvents.project(trace_only), "traceparent")
      refute Map.has_key?(CloudEvents.project(span_only), "traceparent")
    end
  end
end
