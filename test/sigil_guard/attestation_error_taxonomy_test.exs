defmodule SigilGuard.AttestationErrorTaxonomyTest do
  use ExUnit.Case, async: false

  alias __MODULE__.MissingSigner
  alias __MODULE__.Signer
  alias SigilGuard.Attestation
  alias SigilGuard.Attestation.Digest
  alias SigilGuard.Attestation.Statement
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.Config
  alias SigilGuard.ConfigError
  alias SigilGuard.Decision
  alias SigilGuard.ReplayStore
  alias SigilGuard.TrustProfile

  @now ~U[2026-07-03 12:00:00.000Z]
  @payload %{"method" => "tools/call", "params" => %{"name" => "repo_file_write"}}
  @context %{phase: :tool_request, origin: :user, sink: :tool, tool: "repo_file_write"}
  @manifest_digest String.duplicate("d", 64)

  @sp01_taxonomy MapSet.new([
                   :invalid_profile,
                   :unsupported_profile_version,
                   :unknown_statement_type,
                   :invalid_envelope,
                   :invalid_payload_type,
                   :invalid_base64,
                   :duplicate_keyid,
                   :missing_trust_bundle,
                   :unknown_key_id,
                   :invalid_signature,
                   :pae_mismatch,
                   :digest_mismatch,
                   :manifest_digest_mismatch,
                   :unknown_manifest,
                   :expired_attestation,
                   :replay_detected,
                   :unsupported_number_range,
                   :invalid_map,
                   :invalid_payload,
                   :invalid_signer,
                   :legacy_contract_removed
                 ])

  setup do
    ReplayStore.clear()
    on_exit(&ReplayStore.clear/0)
  end

  test "every SP.01 error taxonomy atom is produced by a public API scenario" do
    produced =
      scenarios()
      |> Enum.map(fn {label, fun} -> {label, fun.()} end)
      |> Map.new()

    assert MapSet.new(Map.values(produced)) == @sp01_taxonomy
  end

  defp scenarios do
    %{
      invalid_profile: fn ->
        {:error, reason} = TrustProfile.validate(%{})
        reason
      end,
      unsupported_profile_version: fn ->
        {:ok, statement} = valid_statement()

        {:error, reason} =
          statement
          |> put_in(["predicate", "profile"], "sigil_guard_agent_trust/v2")
          |> TrustProfile.validate()

        reason
      end,
      unknown_statement_type: fn ->
        {:ok, statement} = valid_statement()

        {:error, reason} =
          statement
          |> Map.put("predicateType", "https://sigilguard.dev/attestation/unknown/v1")
          |> TrustProfile.validate()

        reason
      end,
      invalid_envelope: fn ->
        {:error, reason} = Attestation.verify("bad", %{"trusted" => Signer.public_key()})
        reason
      end,
      invalid_payload_type: fn ->
        {:ok, envelope} = signed_statement()

        {:error, reason} =
          Attestation.verify(%{envelope | "payloadType" => "application/json"}, trust())

        reason
      end,
      invalid_base64: fn ->
        {:ok, envelope} = signed_statement()
        {:error, reason} = Attestation.verify(%{envelope | "payload" => "not base64!"}, trust())
        reason
      end,
      duplicate_keyid: fn ->
        {:ok, envelope} = signed_statement()
        [signature] = envelope["signatures"]

        {:error, reason} =
          envelope
          |> Map.put("signatures", [signature, signature])
          |> Attestation.verify(trust())

        reason
      end,
      missing_trust_bundle: fn ->
        {:ok, envelope} = signed_statement()
        {:error, reason} = Attestation.verify(envelope, %{})
        reason
      end,
      unknown_key_id: fn ->
        {:ok, envelope} = signed_statement()
        {:error, reason} = Attestation.verify(envelope, %{"other" => Signer.public_key()})
        reason
      end,
      invalid_signature: fn ->
        {:ok, envelope} = signed_statement()
        [signature] = envelope["signatures"]

        bad_sig = %{
          signature
          | "sig" => Base.url_encode64(:binary.copy(<<0>>, 64), padding: false)
        }

        {:error, reason} = Attestation.verify(%{envelope | "signatures" => [bad_sig]}, trust())
        reason
      end,
      pae_mismatch: fn ->
        {:ok, envelope} = signed_statement()

        {:error, reason} =
          Attestation.verify(envelope, trust(),
            expected_payload_sha256: String.duplicate("0", 64)
          )

        reason
      end,
      digest_mismatch: fn ->
        {:ok, envelope} = signed_statement()

        {:error, reason} =
          Attestation.verify(envelope, trust(),
            payload: put_in(@payload, ["params", "name"], "other_tool"),
            context: @context,
            now: @now
          )

        reason
      end,
      manifest_digest_mismatch: fn ->
        {:ok, envelope} = signed_statement(manifest_digest: @manifest_digest)

        {:error, reason} =
          Attestation.verify(envelope, trust(),
            payload: @payload,
            context: @context,
            manifest_digest: String.duplicate("e", 64),
            now: @now
          )

        reason
      end,
      unknown_manifest: fn ->
        {:ok, envelope} = signed_statement(manifest_digest: @manifest_digest)

        {:error, reason} =
          Attestation.verify(envelope, trust(),
            payload: @payload,
            context: @context,
            now: @now
          )

        reason
      end,
      expired_attestation: fn ->
        {:ok, statement} =
          valid_statement(%{
            "issued_at" => "2026-07-03T11:00:00.000Z",
            "expires_at" => "2026-07-03T11:59:00.000Z"
          })

        {:ok, envelope} = Attestation.sign(statement, Signer, keyid: "trusted")

        {:error, reason} =
          Attestation.verify(envelope, trust(),
            now: @now,
            max_skew_ms: 0
          )

        reason
      end,
      replay_detected: fn ->
        {:ok, envelope} = signed_statement()
        assert {:ok, _} = Attestation.verify(envelope, trust(), now: @now, replay: true)
        {:error, reason} = Attestation.verify(envelope, trust(), now: @now, replay: true)
        reason
      end,
      unsupported_number_range: fn ->
        {:error, reason} = JCS.encode(9_007_199_254_740_992)
        reason
      end,
      invalid_map: fn ->
        {:error, reason} = JCS.encode(%{:a => 1, "a" => 2})
        reason
      end,
      invalid_payload: fn ->
        decision = %Decision{
          verdict: :allowed,
          action: :allow,
          phase: :tool_request,
          risk_level: :low,
          trust_level: :medium
        }

        {:error, reason} = Attestation.from_decision(decision, @context, now: @now)
        reason
      end,
      invalid_signer: fn ->
        {:ok, statement} = valid_statement()
        {:error, reason} = Attestation.sign(statement, MissingSigner)
        reason
      end,
      legacy_contract_removed: fn ->
        try do
          Config.validate!(backend: :elixir)
        rescue
          error in ConfigError -> error.reason
        end
      end
    }
  end

  defp signed_statement(digest_opts \\ []) do
    with {:ok, statement} <- valid_statement(%{}, digest_opts) do
      Attestation.sign(statement, Signer, keyid: "trusted")
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
          "expires_at" => "2026-07-03T12:05:00.000Z"
        },
        predicate_overrides
      )

    Statement.build(predicate_type, predicate, digests)
  end

  defp trust, do: %{"trusted" => Signer.public_key()}

  defmodule Signer do
    @behaviour SigilGuard.Signer
    @seed :crypto.hash(:sha256, "sigilguard-attestation-taxonomy")

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
