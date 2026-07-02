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

    test "rejects expired attestations" do
      assert {:ok, statement} = valid_statement(%{"expires_at" => "2026-07-03T11:59:00.000Z"})
      assert {:ok, envelope} = Attestation.sign(statement, TrustedSigner, keyid: "trusted")

      assert Attestation.verify(envelope, %{"trusted" => TrustedSigner.public_key()}, now: @now) ==
               {:error, :expired_attestation}
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
  end

  describe "negative paths" do
    test "rejects invalid signing inputs" do
      assert Attestation.sign("bad", TrustedSigner) == {:error, :invalid_payload}
      assert {:ok, statement} = valid_statement()
      assert Attestation.sign(statement, MissingSigner) == {:error, :invalid_signer}
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
    end
  end

  defp valid_statement(predicate_overrides \\ %{}) do
    {:ok, predicate_type} = TrustProfile.predicate_type(:tool_request)
    {:ok, digests} = Digest.digests(:tool_request, @payload, @context)

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
