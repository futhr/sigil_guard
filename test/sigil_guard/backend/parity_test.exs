defmodule SigilGuard.Backend.ParityTest do
  @moduledoc """
  Cross-backend parity tests.

  Verifies that the Elixir and NIF backends produce identical outputs
  for all operations. This is the most critical test suite for ensuring
  interoperability between backends.
  """

  use ExUnit.Case, async: true

  @moduletag :nif

  alias SigilGuard.Backend.Elixir, as: ElixirBackend
  alias SigilGuard.Backend.NIF, as: NIFBackend

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
end
