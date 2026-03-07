defmodule SigilGuardTest do
  @moduledoc """
  Tests for the `SigilGuard` top-level facade.

  Verifies that public API functions correctly delegate to the configured
  backend, covering scanning, redaction, and policy verdict operations.
  """

  use ExUnit.Case, async: true

  doctest SigilGuard

  describe "scan/2" do
    test "delegates to Scanner" do
      assert {:ok, "clean"} = SigilGuard.scan("clean")
      assert {:hit, _} = SigilGuard.scan("AKIAIOSFODNN7EXAMPLE")
    end
  end

  describe "scan_and_redact/2" do
    test "returns clean text unchanged" do
      assert SigilGuard.scan_and_redact("nothing here") == "nothing here"
    end

    test "redacts sensitive content" do
      result = SigilGuard.scan_and_redact("key=AKIAIOSFODNN7EXAMPLE")

      assert String.contains?(result, "[AWS_KEY]")
      refute String.contains?(result, "AKIAIOSFODNN7EXAMPLE")
    end
  end

  describe "policy_verdict/3" do
    test "allows low-risk actions for medium trust users" do
      assert :allowed = SigilGuard.policy_verdict("read_file", :medium)
    end

    test "blocks high-risk actions for low trust users" do
      assert :blocked = SigilGuard.policy_verdict("delete_database", :low)
    end

    test "allows high-risk actions for high trust users" do
      assert :allowed = SigilGuard.policy_verdict("delete_database", :high)
    end

    test "returns confirmation for borderline cases" do
      assert {:confirm, reason} = SigilGuard.policy_verdict("create_user", :low)
      assert is_binary(reason)
    end
  end
end
