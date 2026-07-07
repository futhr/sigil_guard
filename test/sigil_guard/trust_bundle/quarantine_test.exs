defmodule SigilGuard.TrustBundle.QuarantineTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.TrustBundle
  alias SigilGuard.TrustBundle.Quarantine

  @now ~U[2026-07-03 12:00:00.000Z]

  setup do
    Quarantine.clear()
    :ok
  end

  describe "record/2" do
    test "normalizes explicit record metadata and evidence refs" do
      record =
        Quarantine.record(:threshold_not_met, %{
          bundle_id: "example-org-trust",
          bundle_digest: String.duplicate("a", 64),
          sequence: 7,
          now: @now,
          evidence: [
            %{"kind" => "checkpoint", "ref" => "audit:1"},
            %{kind: "anchor", ref: "audit:2"},
            %{"kind" => "bad"}
          ]
        })

      assert record == %{
               reason: :threshold_not_met,
               bundle_id: "example-org-trust",
               bundle_digest: String.duplicate("a", 64),
               sequence: 7,
               quarantined_at: "2026-07-03T12:00:00.000Z",
               evidence: [
                 %{kind: "checkpoint", ref: "audit:1"},
                 %{kind: "anchor", ref: "audit:2"}
               ]
             }

      assert Quarantine.list() == [record]
      assert Quarantine.list("example-org-trust") == [record]
      assert Quarantine.list("other") == []
    end

    test "derives digest, bundle id, and sequence from decodable envelopes" do
      envelope = malformed_envelope(bundle_document())
      payload = Base.url_decode64!(envelope["payload"], padding: false)

      record = Quarantine.record(:invalid_envelope, %{envelope: envelope, now: @now})

      assert record.bundle_id == "example-org-trust"
      assert record.sequence == 1
      assert record.bundle_digest == Base.encode16(:crypto.hash(:sha256, payload), case: :lower)
      assert record.evidence == []
    end

    test "accepts direct document and payload metadata shapes" do
      document_record =
        Quarantine.record(:invalid_bundle_format, %{
          document: %{"bundle_id" => "document-bundle", "sequence" => 3},
          now: @now
        })

      payload_record =
        Quarantine.record(:invalid_signature, %{
          payload: "payload bytes",
          now: @now
        })

      atom_payload =
        bundle_document()
        |> malformed_envelope()
        |> Map.fetch!("payload")

      atom_envelope_record =
        Quarantine.record(:invalid_envelope, %{
          envelope: %{payload: atom_payload},
          now: @now
        })

      malformed_envelope_record =
        Quarantine.record(:invalid_envelope, %{envelope: %{payload: 1}, now: @now})

      assert document_record.bundle_id == "document-bundle"
      assert document_record.sequence == nil

      assert payload_record.bundle_digest ==
               Base.encode16(:crypto.hash(:sha256, "payload bytes"), case: :lower)

      assert atom_envelope_record.bundle_id == "example-org-trust"
      assert malformed_envelope_record.bundle_digest == nil
    end
  end

  describe "public load and verify quarantine" do
    test "records verify failures with decoded payload metadata" do
      envelope = malformed_envelope(bundle_document())

      assert TrustBundle.verify(envelope, now: @now) == {:error, :invalid_envelope}

      assert [
               %{
                 reason: :invalid_envelope,
                 bundle_id: "example-org-trust",
                 sequence: 1,
                 quarantined_at: "2026-07-03T12:00:00.000Z"
               }
             ] = Quarantine.list()
    end

    test "records invalid source failures without payload metadata" do
      assert TrustBundle.load({:binary, "not json"}, now: @now) == {:error, :invalid_source}

      assert [
               %{
                 reason: :invalid_source,
                 bundle_id: nil,
                 bundle_digest: nil,
                 sequence: nil,
                 quarantined_at: "2026-07-03T12:00:00.000Z",
                 evidence: []
               }
             ] = Quarantine.list()
    end

    test "records base64 and bundle-format failures as separate records" do
      invalid_base64 = %{
        "payload" => "*",
        "payloadType" => Envelope.payload_type(),
        "signatures" => [%{"keyid" => "key", "sig" => "sig"}]
      }

      invalid_document =
        %{"not" => "a bundle"}
        |> malformed_envelope()
        |> Map.put("signatures", [%{"keyid" => "key", "sig" => "sig"}])

      assert TrustBundle.verify(invalid_base64, now: @now) == {:error, :invalid_base64}
      assert TrustBundle.verify(invalid_document, now: @now) == {:error, :invalid_bundle_format}

      assert Enum.map(Quarantine.list(), & &1.reason) == [:invalid_base64, :invalid_bundle_format]
      assert [nil, digest] = Enum.map(Quarantine.list(), & &1.bundle_digest)
      assert is_binary(digest)
    end

    test "can suppress recording for controlled callers" do
      assert TrustBundle.verify(%{}, now: @now, quarantine: false) == {:error, :invalid_envelope}
      assert Quarantine.list() == []
    end
  end

  defp malformed_envelope(document) do
    {:ok, payload} = JCS.encode(document)

    %{
      "payload" => Base.url_encode64(payload, padding: false),
      "payloadType" => Envelope.payload_type(),
      "signatures" => []
    }
  end

  defp bundle_document do
    %{
      "profile" => "sigil_guard_trust_bundle/v1",
      "bundle_id" => "example-org-trust",
      "sequence" => "1",
      "issued_at" => "2026-07-03T11:00:00.000Z",
      "expires_at" => "2026-07-03T13:00:00.000Z",
      "roles" => %{
        "root" => %{
          "keyids" => ["sha256:" <> String.duplicate("a", 64)],
          "threshold" => 1,
          "version" => "1",
          "expires_at" => "2027-07-03T12:00:00.000Z"
        },
        "delegates" => [
          %{
            "name" => "bundle",
            "keyids" => ["sha256:" <> String.duplicate("a", 64)],
            "threshold" => 1,
            "expires_at" => "2026-07-03T14:00:00.000Z"
          }
        ]
      },
      "keys" => %{},
      "rollback_floor" => "1"
    }
  end
end
