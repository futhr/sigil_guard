defmodule SigilGuard.AttestationSignVerifyTest do
  use ExUnit.Case, async: true

  alias __MODULE__.TrustedSigner
  alias __MODULE__.WitnessSigner
  alias SigilGuard.Attestation
  alias SigilGuard.Attestation.Digest
  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Attestation.Statement
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.ReplayStore
  alias SigilGuard.TrustProfile

  @now ~U[2026-07-03 12:00:00.000Z]
  @expires_at "2026-07-03T12:05:00.000Z"
  @payload %{"method" => "tools/call", "params" => %{"name" => "repo_file_write"}}
  @context %{phase: :tool_request, origin: :user, sink: :tool, tool: "repo_file_write"}
  @manifest_digest String.duplicate("d", 64)

  setup do
    ReplayStore.clear()
    on_exit(&ReplayStore.clear/0)
  end

  describe "sign/3 and verify/3" do
    test "signs and verifies a profile-valid statement with derived keyid" do
      assert {:ok, statement} = valid_statement()
      assert {:ok, envelope} = Attestation.sign(statement, TrustedSigner)

      keyid = Envelope.keyid(TrustedSigner.public_key())
      assert [%{"keyid" => ^keyid}] = envelope["signatures"]

      assert Attestation.verify(envelope, %{keyid => TrustedSigner.public_key()},
               payload: @payload,
               context: @context,
               now: @now
             ) == {:ok, statement}
    end

    test "honors explicit keyid and deterministic sign options" do
      assert {:ok, statement} = valid_statement(%{"nonce" => nil, "issued_at" => nil})

      assert {:ok, envelope} =
               Attestation.sign(statement, TrustedSigner,
                 keyid: "explicit",
                 now: @now,
                 nonce: "n-1"
               )

      assert [%{"keyid" => "explicit"}] = envelope["signatures"]

      assert {:ok, verified} =
               Attestation.verify(envelope, %{"explicit" => TrustedSigner.public_key()},
                 now: @now
               )

      assert get_in(verified, ["predicate", "issued_at"]) == DateTime.to_iso8601(@now)
      assert get_in(verified, ["predicate", "nonce"]) == "n-1"

      assert {:ok, string_now_envelope} =
               Attestation.sign(statement, TrustedSigner,
                 keyid: "explicit",
                 now: DateTime.to_iso8601(@now),
                 nonce: "n-2"
               )

      assert {:ok, string_now_verified} =
               Attestation.verify(
                 string_now_envelope,
                 %{"explicit" => TrustedSigner.public_key()},
                 now: @now
               )

      assert get_in(string_now_verified, ["predicate", "issued_at"]) == DateTime.to_iso8601(@now)
      assert get_in(string_now_verified, ["predicate", "nonce"]) == "n-2"
    end

    test "tolerates unresolved witness signatures when one signature resolves" do
      assert {:ok, statement} = valid_statement()
      assert {:ok, payload} = JCS.encode(statement)

      assert {:ok, envelope} =
               Envelope.sign_many(payload, [
                 {TrustedSigner, "trusted"},
                 {WitnessSigner, "witness"}
               ])

      assert Attestation.verify(envelope, %{"trusted" => TrustedSigner.public_key()}, now: @now) ==
               {:ok, statement}
    end

    test "checks expected payload sha256 before key resolution" do
      assert {:ok, statement} = valid_statement()
      assert {:ok, envelope} = Attestation.sign(statement, TrustedSigner, keyid: "trusted")

      assert Attestation.verify(envelope, %{"trusted" => TrustedSigner.public_key()},
               expected_payload_sha256: String.duplicate("0", 64),
               now: @now
             ) == {:error, :pae_mismatch}
    end

    test "recomputes statement digests when payload and context are supplied" do
      assert {:ok, statement} = valid_statement()
      assert {:ok, envelope} = Attestation.sign(statement, TrustedSigner, keyid: "trusted")

      assert Attestation.verify(envelope, %{"trusted" => TrustedSigner.public_key()},
               payload: %{"method" => "tools/call", "params" => %{"name" => "other_tool"}},
               context: @context,
               now: @now
             ) == {:error, :digest_mismatch}
    end

    test "rejects payload, context, action, and manifest tampering" do
      assert {:ok, statement} = valid_statement(%{}, manifest_digest: @manifest_digest)
      assert {:ok, envelope} = Attestation.sign(statement, TrustedSigner, keyid: "trusted")

      trust_material = %{"trusted" => TrustedSigner.public_key()}

      assert Attestation.verify(envelope, trust_material,
               payload: @payload,
               context: @context,
               manifest_digest: @manifest_digest,
               now: @now
             ) == {:ok, statement}

      assert Attestation.verify(envelope, trust_material,
               payload: Map.put(@payload, "id", 43),
               context: @context,
               manifest_digest: @manifest_digest,
               now: @now
             ) == {:error, :digest_mismatch}

      assert Attestation.verify(envelope, trust_material,
               payload: @payload,
               context: Map.put(@context, :sink, :repo),
               manifest_digest: @manifest_digest,
               now: @now
             ) == {:error, :digest_mismatch}

      assert Attestation.verify(envelope, trust_material,
               payload: put_in(@payload, ["params", "name"], "other_tool"),
               context: @context,
               manifest_digest: @manifest_digest,
               now: @now
             ) == {:error, :digest_mismatch}

      assert Attestation.verify(envelope, trust_material,
               payload: @payload,
               context: @context,
               manifest_digest: String.duplicate("e", 64),
               now: @now
             ) == {:error, :manifest_digest_mismatch}
    end

    test "rejects expired attestations" do
      assert {:ok, statement} =
               valid_statement(%{
                 "issued_at" => "2026-07-03T11:00:00.000Z",
                 "expires_at" => "2026-07-03T11:59:00.000Z"
               })

      assert {:ok, envelope} = Attestation.sign(statement, TrustedSigner, keyid: "trusted")

      assert Attestation.verify(envelope, %{"trusted" => TrustedSigner.public_key()},
               now: @now,
               max_skew_ms: 0
             ) == {:error, :expired_attestation}
    end

    test "honors expiration skew boundaries" do
      assert {:ok, statement} =
               valid_statement(%{
                 "issued_at" => "2026-07-03T11:00:00.000Z",
                 "expires_at" => "2026-07-03T11:59:00.000Z"
               })

      assert {:ok, envelope} = Attestation.sign(statement, TrustedSigner, keyid: "trusted")

      assert Attestation.verify(envelope, %{"trusted" => TrustedSigner.public_key()},
               now: @now,
               max_skew_ms: 60_000
             ) == {:ok, statement}

      assert Attestation.verify(envelope, %{"trusted" => TrustedSigner.public_key()},
               now: DateTime.add(@now, 1, :millisecond),
               max_skew_ms: 60_000
             ) == {:error, :expired_attestation}
    end

    test "rejects future-issued and inverted lifetime attestations" do
      assert {:ok, future_statement} =
               valid_statement(%{
                 "issued_at" => "2026-07-03T12:01:00.001Z",
                 "expires_at" => "2026-07-03T12:05:00.000Z"
               })

      assert {:ok, future_envelope} =
               Attestation.sign(future_statement, TrustedSigner, keyid: "trusted")

      assert Attestation.verify(future_envelope, %{"trusted" => TrustedSigner.public_key()},
               now: @now,
               max_skew_ms: 60_000
             ) == {:error, :expired_attestation}

      assert {:ok, inverted_statement} =
               valid_statement(%{
                 "issued_at" => "2026-07-03T12:05:00.000Z",
                 "expires_at" => "2026-07-03T12:05:00.000Z"
               })

      assert {:ok, inverted_envelope} =
               Attestation.sign(inverted_statement, TrustedSigner, keyid: "trusted")

      assert Attestation.verify(inverted_envelope, %{"trusted" => TrustedSigner.public_key()},
               now: @now
             ) == {:error, :invalid_payload}
    end

    test "can consume attestation nonces for replay protection" do
      assert {:ok, statement} = valid_statement(%{"nonce" => "replay-nonce"})
      assert {:ok, envelope} = Attestation.sign(statement, TrustedSigner, keyid: "trusted")

      opts = [now: @now, consume: true, ttl_ms: 60_000]

      assert Attestation.verify(envelope, %{"trusted" => TrustedSigner.public_key()}, opts) ==
               {:ok, statement}

      assert Attestation.verify(envelope, %{"trusted" => TrustedSigner.public_key()}, opts) ==
               {:error, :replay_detected}
    end

    test "rejects malformed replay protection inputs" do
      assert {:ok, missing_actor_statement} =
               valid_statement(%{
                 "actor" => %{"trust_level" => "medium"},
                 "nonce" => "missing-actor"
               })

      assert {:ok, missing_actor_envelope} =
               Attestation.sign(missing_actor_statement, TrustedSigner, keyid: "trusted")

      assert Attestation.verify(
               missing_actor_envelope,
               %{"trusted" => TrustedSigner.public_key()},
               now: @now,
               replay: true
             ) == {:error, :invalid_payload}

      assert {:ok, statement} = valid_statement(%{"nonce" => "bad-replay-ttl"})
      assert {:ok, envelope} = Attestation.sign(statement, TrustedSigner, keyid: "trusted")

      assert Attestation.verify(envelope, %{"trusted" => TrustedSigner.public_key()},
               now: @now,
               replay: true,
               replay_ttl_ms: 0
             ) == {:error, :invalid_payload}
    end

    test "uses replay option and remaining lifetime ttl for nonce protection" do
      assert {:ok, statement} = valid_statement(%{"nonce" => "replay-option-nonce"})
      assert {:ok, envelope} = Attestation.sign(statement, TrustedSigner, keyid: "trusted")

      opts = [now: @now, replay: true]

      assert Attestation.verify(envelope, %{"trusted" => TrustedSigner.public_key()}, opts) ==
               {:ok, statement}

      assert Attestation.verify(envelope, %{"trusted" => TrustedSigner.public_key()}, opts) ==
               {:error, :replay_detected}
    end
  end

  describe "negative paths" do
    test "rejects invalid signing inputs" do
      assert Attestation.sign("bad", TrustedSigner) == {:error, :invalid_payload}
      assert {:ok, statement} = valid_statement()
      assert Attestation.sign(statement, MissingSigner) == {:error, :invalid_signer}

      assert {:ok, ignored_now_envelope} = Attestation.sign(statement, TrustedSigner, now: :bad)
      assert {:ok, default_envelope} = Attestation.sign(statement, TrustedSigner)
      assert ignored_now_envelope["payload"] == default_envelope["payload"]
    end

    test "rejects missing or unresolvable trust material" do
      assert {:ok, statement} = valid_statement()
      assert {:ok, envelope} = Attestation.sign(statement, TrustedSigner, keyid: "trusted")

      assert Attestation.verify(envelope, %{}, now: @now) == {:error, :missing_trust_bundle}

      assert Attestation.verify(envelope, %{"other" => TrustedSigner.public_key()}, now: @now) ==
               {:error, :unknown_key_id}
    end

    test "rejects invalid signatures and malformed envelopes" do
      assert {:ok, statement} = valid_statement()
      assert {:ok, envelope} = Attestation.sign(statement, TrustedSigner, keyid: "trusted")

      tampered = %{envelope | "payload" => Base.url_encode64(~s({"bad":true}), padding: false)}

      assert Attestation.verify(tampered, %{"trusted" => TrustedSigner.public_key()}, now: @now) ==
               {:error, :invalid_signature}

      assert Attestation.verify(%{"payload" => "x"}, %{"trusted" => TrustedSigner.public_key()}) ==
               {:error, :invalid_envelope}

      malformed_signature = %{
        "payload" => envelope["payload"],
        "payloadType" => envelope["payloadType"],
        "signatures" => [%{"keyid" => "trusted"}]
      }

      assert Attestation.verify(malformed_signature, %{"trusted" => TrustedSigner.public_key()}) ==
               {:error, :invalid_envelope}

      invalid_payload_type = %{envelope | "payloadType" => "application/json"}

      assert Attestation.verify(invalid_payload_type, %{"trusted" => TrustedSigner.public_key()}) ==
               {:error, :invalid_payload_type}

      duplicate_keyid = %{
        envelope
        | "signatures" => envelope["signatures"] ++ envelope["signatures"]
      }

      assert Attestation.verify(duplicate_keyid, %{"trusted" => TrustedSigner.public_key()}) ==
               {:error, :duplicate_keyid}

      invalid_base64 = %{envelope | "payload" => "not base64!"}

      assert Attestation.verify(invalid_base64, %{"trusted" => TrustedSigner.public_key()}) ==
               {:error, :invalid_base64}

      assert {:ok, list_payload_envelope} =
               Envelope.sign("[1,2,3]", TrustedSigner, keyid: "trusted")

      assert Attestation.verify(list_payload_envelope, %{"trusted" => TrustedSigner.public_key()},
               now: @now
             ) == {:error, :invalid_profile}

      assert {:ok, non_json_envelope} = Envelope.sign("not-json", TrustedSigner, keyid: "trusted")

      assert Attestation.verify(non_json_envelope, %{"trusted" => TrustedSigner.public_key()},
               now: @now
             ) == {:error, :invalid_profile}

      assert Attestation.verify(envelope, %{"trusted" => TrustedSigner.public_key()},
               expected_payload_sha256: :bad,
               now: @now
             ) == {:error, :pae_mismatch}

      assert Attestation.verify(envelope, %{"trusted" => TrustedSigner.public_key()},
               now: "bad-now"
             ) == {:error, :invalid_payload}

      assert Attestation.verify(envelope, %{"trusted" => TrustedSigner.public_key()},
               now: @now,
               max_skew_ms: -1
             ) == {:error, :invalid_payload}
    end

    test "returns taxonomy atoms for malformed envelope shapes" do
      assert {:ok, statement} = valid_statement()
      assert {:ok, envelope} = Attestation.sign(statement, TrustedSigner, keyid: "trusted")
      trust_material = %{"trusted" => TrustedSigner.public_key()}

      cases = [
        {"non-map envelope", "bad", :invalid_envelope},
        {"non-string payloadType", %{envelope | "payloadType" => 42}, :invalid_envelope},
        {"wrong payloadType", %{envelope | "payloadType" => "application/json"},
         :invalid_payload_type},
        {"empty signatures", %{envelope | "signatures" => []}, :invalid_envelope},
        {"mistyped signatures", %{envelope | "signatures" => "bad"}, :invalid_envelope},
        {"mistyped signature entry", %{envelope | "signatures" => ["bad"]}, :invalid_envelope},
        {"truncated payload base64", %{envelope | "payload" => "not base64!"}, :invalid_base64},
        {
          "truncated signature base64",
          %{envelope | "signatures" => [%{"keyid" => "trusted", "sig" => "not base64!"}]},
          :invalid_base64
        }
      ]

      for {label, malformed, reason} <- cases do
        assert Attestation.verify(malformed, trust_material, now: @now) == {:error, reason},
               label
      end
    end

    test "returns taxonomy atoms for signed non-Statement JSON payloads" do
      trust_material = %{"trusted" => TrustedSigner.public_key()}

      assert Attestation.verify(signed_payload!(~s({"bad":true})), trust_material, now: @now) ==
               {:error, :invalid_profile}

      assert Attestation.verify(signed_payload!(~s(["bad"])), trust_material, now: @now) ==
               {:error, :invalid_profile}

      assert Attestation.verify(signed_payload!("not json"), trust_material, now: @now) ==
               {:error, :invalid_profile}
    end
  end

  defp valid_statement(predicate_overrides \\ %{}, digest_opts \\ []) do
    {:ok, predicate_type} = TrustProfile.predicate_type(:tool_request)
    {:ok, digests} = Digest.digests(:tool_request, @payload, @context, digest_opts)

    predicate =
      Map.merge(
        %{
          "profile" => TrustProfile.profile_id(),
          "statement_type" => "tool_request",
          "actor" => %{"id" => "spiffe://agents/requester", "trust_level" => "medium"},
          "verdict" => "allow",
          "nonce" => "nonce-1",
          "issued_at" => DateTime.to_iso8601(@now),
          "expires_at" => @expires_at
        },
        Map.reject(predicate_overrides, fn {_, value} -> is_nil(value) end)
      )

    Statement.build(predicate_type, predicate, digests)
  end

  defp signed_payload!(payload) do
    {:ok, envelope} = Envelope.sign(payload, TrustedSigner, keyid: "trusted")
    envelope
  end

  defmodule TrustedSigner do
    @behaviour SigilGuard.Signer

    @seed :crypto.hash(:sha256, "sigilguard-attestation-trusted")

    @impl SigilGuard.Signer
    def sign(message) do
      {_, private_key} = keypair()
      :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])
    end

    @impl SigilGuard.Signer
    def public_key do
      {public_key, _} = keypair()
      public_key
    end

    defp keypair do
      :crypto.generate_key(:eddsa, :ed25519, @seed)
    end
  end

  defmodule WitnessSigner do
    @behaviour SigilGuard.Signer

    @seed :crypto.hash(:sha256, "sigilguard-attestation-witness")

    @impl SigilGuard.Signer
    def sign(message) do
      {_, private_key} = keypair()
      :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])
    end

    @impl SigilGuard.Signer
    def public_key do
      {public_key, _} = keypair()
      public_key
    end

    defp keypair do
      :crypto.generate_key(:eddsa, :ed25519, @seed)
    end
  end

  defmodule MissingSigner do
  end
end
