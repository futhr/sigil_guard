defmodule SigilGuard.Backend.ElixirTest do
  @moduledoc """
  Tests for `SigilGuard.Backend.Elixir`.

  Verifies that the pure-Elixir backend correctly delegates all
  `SigilGuard.Backend` callbacks to their respective modules (Scanner,
  Envelope, Policy, Audit).
  """

  use ExUnit.Case, async: true

  alias SigilGuard.Backend.Elixir, as: ElixirBackend

  describe "scan/2" do
    test "delegates to Scanner - clean text" do
      assert {:ok, "safe"} = ElixirBackend.scan("safe", [])
    end

    test "delegates to Scanner - detects secrets" do
      assert {:hit, hits} = ElixirBackend.scan("AKIAIOSFODNN7EXAMPLE", [])
      assert length(hits) > 0
    end
  end

  describe "redact/3" do
    test "delegates to Scanner" do
      hits = [%{offset: 0, length: 3, match: "foo", replacement_hint: "[X]"}]
      assert "[X] bar" = ElixirBackend.redact("foo bar", hits, [])
    end
  end

  describe "scan_and_redact/2" do
    test "delegates to Scanner" do
      assert "safe" = ElixirBackend.scan_and_redact("safe", [])
    end
  end

  describe "canonical_bytes/4" do
    test "delegates to Envelope" do
      bytes =
        ElixirBackend.canonical_bytes(
          "did:sigil:alice",
          :allowed,
          "2024-01-01T00:00:00.000Z",
          "abcd1234"
        )

      assert is_binary(bytes)
      assert bytes =~ "identity"
      assert bytes =~ "verdict"
    end
  end

  describe "envelope_sign/3" do
    test "delegates to Envelope" do
      envelope =
        ElixirBackend.envelope_sign("did:sigil:alice", :allowed, signer: SigilGuard.TestSigner)

      assert envelope["identity"] == "did:sigil:alice"
      assert envelope["verdict"] == "Allowed"
      assert is_binary(envelope["signature"])
    end
  end

  describe "envelope_verify/2" do
    test "delegates to Envelope" do
      envelope =
        ElixirBackend.envelope_sign("did:sigil:alice", :allowed, signer: SigilGuard.TestSigner)

      assert :ok =
               ElixirBackend.envelope_verify(envelope, SigilGuard.TestSigner.public_key_b64u())
    end
  end

  describe "evaluate_policy/3" do
    test "delegates to Policy" do
      assert :allowed = ElixirBackend.evaluate_policy("read_file", :authenticated, [])
      assert :blocked = ElixirBackend.evaluate_policy("delete_database", :anonymous, [])
    end
  end

  describe "classify_risk/2" do
    test "delegates to Policy" do
      assert :low = ElixirBackend.classify_risk("read_file", [])
      assert :critical = ElixirBackend.classify_risk("delete_database", [])
    end
  end

  describe "audit_sign_event/3" do
    test "delegates to Audit" do
      event = SigilGuard.Audit.new_event("test", "actor", "action", "success")
      key = :crypto.strong_rand_bytes(32)
      signed = ElixirBackend.audit_sign_event(event, key, nil)
      assert signed.hmac != nil
    end
  end

  describe "audit_verify_chain/2" do
    test "delegates to Audit" do
      events = [
        SigilGuard.Audit.new_event("test", "actor", "a1", "ok"),
        SigilGuard.Audit.new_event("test", "actor", "a2", "ok")
      ]

      key = :crypto.strong_rand_bytes(32)
      signed = SigilGuard.Audit.build_chain(events, key)
      assert :ok = ElixirBackend.audit_verify_chain(signed, key)
    end
  end
end
