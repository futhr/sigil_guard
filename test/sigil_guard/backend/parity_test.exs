defmodule SigilGuard.Backend.ParityTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Backend.Elixir, as: ElixirBackend
  alias SigilGuard.Backend.NIF, as: NIFBackend

  @moduletag :nif

  # -- Scanning Parity --

  describe "scan parity" do
    test "both backends return :ok for clean text" do
      text = "This is completely safe text with no secrets"
      assert {:ok, ^text} = ElixirBackend.scan(text, [])
      assert {:ok, ^text} = NIFBackend.scan(text, [])
    end

    test "both backends detect AWS access keys" do
      text = "AKIAIOSFODNN7EXAMPLE"
      {:hit, elixir_hits} = ElixirBackend.scan(text, [])
      {:hit, nif_hits} = NIFBackend.scan(text, [])

      assert length(elixir_hits) == length(nif_hits)

      # Compare hit properties (NIF returns maps with string/atom keys, Elixir returns maps)
      for {eh, nh} <- Enum.zip(elixir_hits, nif_hits) do
        assert eh.name == nh[:name]
        assert eh.category == nh[:category]
        assert eh.severity == nh[:severity]
        assert eh.offset == nh[:offset]
        assert eh.length == nh[:length]
      end
    end

    test "both backends detect bearer tokens" do
      text = "Authorization: Bearer sk-abc123def456ghi789jkl012mno345"
      {:hit, elixir_hits} = ElixirBackend.scan(text, [])
      {:hit, nif_hits} = NIFBackend.scan(text, [])

      assert length(elixir_hits) == length(nif_hits)
    end

    test "both backends detect database URIs" do
      text = "postgres://admin:secret@db.example.com:5432/production"
      {:hit, elixir_hits} = ElixirBackend.scan(text, [])
      {:hit, nif_hits} = NIFBackend.scan(text, [])

      assert length(elixir_hits) == length(nif_hits)
    end

    test "both backends detect private keys" do
      text = "-----BEGIN PRIVATE KEY-----\nMIIEvgIB..."
      {:hit, elixir_hits} = ElixirBackend.scan(text, [])
      {:hit, nif_hits} = NIFBackend.scan(text, [])

      assert length(elixir_hits) == length(nif_hits)
    end
  end

  describe "scan_and_redact parity" do
    test "both backends return clean text unchanged" do
      text = "safe text"
      assert text == ElixirBackend.scan_and_redact(text, [])
      assert text == NIFBackend.scan_and_redact(text, [])
    end

    test "both backends redact AWS keys with same hint" do
      text = "key=AKIAIOSFODNN7EXAMPLE"
      elixir_result = ElixirBackend.scan_and_redact(text, [])
      nif_result = NIFBackend.scan_and_redact(text, [])

      # Both should replace the AWS key with [AWS_KEY]
      refute elixir_result =~ "AKIAIOSFODNN7EXAMPLE"
      refute nif_result =~ "AKIAIOSFODNN7EXAMPLE"
      assert elixir_result =~ "[AWS_KEY]"
      assert nif_result =~ "[AWS_KEY]"
    end
  end

  # -- Canonical Bytes Parity --

  describe "canonical_bytes parity" do
    test "identical output for same inputs" do
      identity = "did:sigil:alice"
      verdict = :allowed
      timestamp = "2024-01-01T00:00:00.000Z"
      nonce = "abcdef1234567890abcdef1234567890"

      elixir_bytes = ElixirBackend.canonical_bytes(identity, verdict, timestamp, nonce)
      nif_bytes = NIFBackend.canonical_bytes(identity, verdict, timestamp, nonce)

      assert elixir_bytes == nif_bytes
    end

    test "identical output for blocked verdict" do
      identity = "did:sigil:bob"
      verdict = :blocked
      timestamp = "2024-06-15T12:30:45.123Z"
      nonce = "deadbeef12345678deadbeef12345678"

      elixir_bytes = ElixirBackend.canonical_bytes(identity, verdict, timestamp, nonce)
      nif_bytes = NIFBackend.canonical_bytes(identity, verdict, timestamp, nonce)

      assert elixir_bytes == nif_bytes
    end

    test "identical output for scanned verdict" do
      identity = "did:web:scanner.example.com"
      verdict = :scanned
      timestamp = "2025-12-31T23:59:59.999Z"
      nonce = "00000000000000000000000000000000"

      elixir_bytes = ElixirBackend.canonical_bytes(identity, verdict, timestamp, nonce)
      nif_bytes = NIFBackend.canonical_bytes(identity, verdict, timestamp, nonce)

      assert elixir_bytes == nif_bytes
    end

    test "handles special characters in identity" do
      identity = "did:sigil:alice+bob@example.com/path?q=1&r=2"
      verdict = :allowed
      timestamp = "2024-01-01T00:00:00.000Z"
      nonce = "1234567890abcdef1234567890abcdef"

      elixir_bytes = ElixirBackend.canonical_bytes(identity, verdict, timestamp, nonce)
      nif_bytes = NIFBackend.canonical_bytes(identity, verdict, timestamp, nonce)

      assert elixir_bytes == nif_bytes
    end
  end

  # -- Policy Parity --

  describe "policy parity" do
    @actions [
      "read_file",
      "get_data",
      "list_users",
      "search_records",
      "create_user",
      "modify_config",
      "send_email",
      "write_file",
      "update_record",
      "execute_command",
      "run_script",
      "delete_database",
      "drop_table",
      "destroy_cluster",
      "unknown_action"
    ]

    @trust_levels [:low, :medium, :high]

    test "classify_risk produces identical results" do
      for action <- @actions do
        elixir_risk = ElixirBackend.classify_risk(action, [])
        nif_risk = NIFBackend.classify_risk(action, [])

        assert elixir_risk == nif_risk,
               "Risk mismatch for #{action}: elixir=#{elixir_risk}, nif=#{nif_risk}"
      end
    end

    test "evaluate_policy produces identical results" do
      for action <- @actions, trust <- @trust_levels do
        elixir_verdict = ElixirBackend.evaluate_policy(action, trust, [])
        nif_verdict = NIFBackend.evaluate_policy(action, trust, [])

        assert elixir_verdict == nif_verdict,
               "Policy mismatch for #{action}/#{trust}: elixir=#{inspect(elixir_verdict)}, nif=#{inspect(nif_verdict)}"
      end
    end
  end

  # -- Envelope Verify Parity --

  describe "envelope_verify parity on malformed input" do
    @valid_key Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

    test "identical error for missing fields" do
      for field <- ~w(identity verdict timestamp nonce signature) do
        broken = Map.delete(parity_envelope(), field)

        assert {:error, :missing_field} = ElixirBackend.envelope_verify(broken, @valid_key)
        assert {:error, :missing_field} = NIFBackend.envelope_verify(broken, @valid_key)
      end
    end

    test "identical error for unknown verdicts" do
      tampered = Map.put(parity_envelope(), "verdict", "allowed")

      assert {:error, :invalid_verdict} = ElixirBackend.envelope_verify(tampered, @valid_key)
      assert {:error, :invalid_verdict} = NIFBackend.envelope_verify(tampered, @valid_key)
    end

    test "identical error for invalid base64 key" do
      envelope = parity_envelope()

      assert {:error, :invalid_base64} =
               ElixirBackend.envelope_verify(envelope, "not!valid!b64")

      assert {:error, :invalid_base64} = NIFBackend.envelope_verify(envelope, "not!valid!b64")
    end

    test "identical error for wrong-size key" do
      envelope = parity_envelope()
      short_key = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

      assert {:error, :invalid_key} = ElixirBackend.envelope_verify(envelope, short_key)
      assert {:error, :invalid_key} = NIFBackend.envelope_verify(envelope, short_key)
    end

    test "identical error for wrong-size signature" do
      short_sig = Base.url_encode64(:crypto.strong_rand_bytes(10), padding: false)
      tampered = Map.put(parity_envelope(), "signature", short_sig)

      assert {:error, :invalid_signature} = ElixirBackend.envelope_verify(tampered, @valid_key)
      assert {:error, :invalid_signature} = NIFBackend.envelope_verify(tampered, @valid_key)
    end

    test "identical error for wrong key" do
      envelope = parity_envelope()
      other_key = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

      assert ElixirBackend.envelope_verify(envelope, other_key) ==
               NIFBackend.envelope_verify(envelope, other_key)
    end
  end

  # -- Audit Parity --

  describe "audit parity" do
    @audit_key :crypto.strong_rand_bytes(32)

    test "audit_sign_event produces identical HMACs" do
      event = SigilGuard.Audit.new_event("test", "alice", "read_file", "ok")

      genesis_elixir = ElixirBackend.audit_sign_event(event, @audit_key, nil)
      genesis_nif = NIFBackend.audit_sign_event(event, @audit_key, nil)

      assert genesis_elixir.hmac == genesis_nif.hmac
      assert genesis_elixir.prev_hmac == genesis_nif.prev_hmac

      linked_elixir = ElixirBackend.audit_sign_event(event, @audit_key, genesis_elixir.hmac)
      linked_nif = NIFBackend.audit_sign_event(event, @audit_key, genesis_elixir.hmac)

      assert linked_elixir.hmac == linked_nif.hmac
    end

    test "audit_verify_chain agrees on valid chains" do
      chain = signed_chain(3)

      assert ElixirBackend.audit_verify_chain(chain, @audit_key) ==
               NIFBackend.audit_verify_chain(chain, @audit_key)

      assert :ok = NIFBackend.audit_verify_chain(chain, @audit_key)
    end

    test "audit_verify_chain agrees on tampered chains" do
      tampered =
        signed_chain(3)
        |> List.update_at(1, fn event -> %{event | action: "tampered"} end)

      assert {:broken, 1} = ElixirBackend.audit_verify_chain(tampered, @audit_key)
      assert {:broken, 1} = NIFBackend.audit_verify_chain(tampered, @audit_key)
    end

    test "audit_verify_chain agrees on head deletion" do
      [_ | rest] = signed_chain(3)

      assert {:broken, 0} = ElixirBackend.audit_verify_chain(rest, @audit_key)
      assert {:broken, 0} = NIFBackend.audit_verify_chain(rest, @audit_key)
    end

    test "audit_verify_chain agrees on middle deletion" do
      truncated = List.delete_at(signed_chain(3), 1)

      assert {:broken, 1} = ElixirBackend.audit_verify_chain(truncated, @audit_key)
      assert {:broken, 1} = NIFBackend.audit_verify_chain(truncated, @audit_key)
    end

    test "audit_verify_chain agrees on unsigned events" do
      unsigned_tail =
        signed_chain(2)
        |> List.update_at(1, fn event -> %{event | hmac: nil} end)

      assert {:broken, 1} = ElixirBackend.audit_verify_chain(unsigned_tail, @audit_key)
      assert {:broken, 1} = NIFBackend.audit_verify_chain(unsigned_tail, @audit_key)
    end
  end

  defp signed_chain(count) do
    1..count
    |> Enum.map(&SigilGuard.Audit.new_event("test", "alice", "action#{&1}", "ok"))
    |> SigilGuard.Audit.build_chain(@audit_key)
  end

  defp parity_envelope do
    SigilGuard.Envelope.sign("did:sigil:parity", :allowed,
      signer: SigilGuard.TestSigner,
      timestamp: "2024-06-15T10:30:00.000Z",
      nonce: "aabbccdd11223344aabbccdd11223344"
    )
  end
end
