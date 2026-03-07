defmodule SigilGuard.Backend.NIFTest do
  @moduledoc """
  Tests for `SigilGuard.Backend.NIF`.

  Unit tests for the Rust NIF backend covering scanning, envelope
  operations, policy evaluation, and audit chain verification.
  The NIF is auto-compiled via Rustler during `mix compile`.
  """

  use ExUnit.Case, async: true

  alias SigilGuard.Backend.NIF, as: NIFBackend

  describe "scan/2" do
    test "returns :ok for clean text" do
      assert {:ok, "safe"} = NIFBackend.scan("safe", [])
    end

    test "detects AWS access keys" do
      assert {:hit, hits} = NIFBackend.scan("AKIAIOSFODNN7EXAMPLE", [])
      assert length(hits) > 0
      hit = hd(hits)
      assert hit[:name] == "aws_access_key"
      assert hit[:category] == "credential"
      assert hit[:severity] == :high
    end

    test "detects bearer tokens" do
      assert {:hit, hits} = NIFBackend.scan("Bearer sk-abc123def456ghi789jkl012", [])
      assert length(hits) > 0
    end

    test "detects database URIs" do
      assert {:hit, hits} = NIFBackend.scan("postgres://user:pass@localhost/db", [])
      assert length(hits) > 0
    end

    test "detects private keys" do
      assert {:hit, _} = NIFBackend.scan("-----BEGIN PRIVATE KEY-----", [])
    end

    test "returns hits sorted by offset" do
      text = "AKIAIOSFODNN7EXAMPLE and Bearer sk-longtoken1234567890abc"
      assert {:hit, hits} = NIFBackend.scan(text, [])
      offsets = Enum.map(hits, & &1[:offset])
      assert offsets == Enum.sort(offsets)
    end
  end

  describe "scan_and_redact/2" do
    test "returns clean text unchanged" do
      assert "safe text" = NIFBackend.scan_and_redact("safe text", [])
    end

    test "redacts detected secrets" do
      result = NIFBackend.scan_and_redact("AKIAIOSFODNN7EXAMPLE", [])
      refute result =~ "AKIAIOSFODNN7EXAMPLE"
      assert result =~ "[AWS_KEY]"
    end

    test "redacts database URIs" do
      result = NIFBackend.scan_and_redact("postgres://user:pass@localhost/db", [])
      refute result =~ "postgres://"
      assert result =~ "[DATABASE_URI]"
    end
  end

  describe "redact/3" do
    test "redacts hits by offset and length" do
      hits = [%{offset: 0, length: 3, replacement_hint: "[X]"}]
      assert "[X] bar" = NIFBackend.redact("foo bar", hits, [])
    end

    test "handles multiple hits" do
      hits = [
        %{offset: 0, length: 3, replacement_hint: "[A]"},
        %{offset: 4, length: 3, replacement_hint: "[B]"}
      ]

      assert "[A] [B]" = NIFBackend.redact("foo bar", hits, [])
    end
  end

  describe "canonical_bytes/4" do
    test "produces valid canonical JSON" do
      bytes =
        NIFBackend.canonical_bytes(
          "did:sigil:alice",
          :allowed,
          "2024-01-01T00:00:00.000Z",
          "abcd1234"
        )

      assert is_binary(bytes)
      assert bytes =~ "identity"
      assert bytes =~ "verdict"
      assert bytes =~ "allowed"
    end

    test "encodes verdict correctly" do
      bytes =
        NIFBackend.canonical_bytes("did:sigil:bob", :blocked, "2024-01-01T00:00:00.000Z", "beef")

      assert bytes =~ "blocked"
    end
  end

  describe "evaluate_policy/3" do
    test "allows low-risk actions for medium trust users" do
      assert :allowed = NIFBackend.evaluate_policy("read_file", :medium, [])
    end

    test "blocks high-risk actions for low trust users" do
      assert :blocked = NIFBackend.evaluate_policy("delete_database", :low, [])
    end

    test "allows high-risk actions for high trust users" do
      assert :allowed = NIFBackend.evaluate_policy("delete_database", :high, [])
    end
  end

  describe "classify_risk/2" do
    test "classifies read actions as low risk" do
      assert :low = NIFBackend.classify_risk("read_file", [])
    end

    test "classifies delete actions as high risk" do
      assert :high = NIFBackend.classify_risk("delete_database", [])
    end

    test "classifies write actions as medium risk" do
      assert :medium = NIFBackend.classify_risk("write_file", [])
    end

    test "classifies create actions as medium risk" do
      assert :medium = NIFBackend.classify_risk("create_user", [])
    end

    test "defaults to medium for unknown actions" do
      assert :medium = NIFBackend.classify_risk("unknown_action", [])
    end
  end
end
