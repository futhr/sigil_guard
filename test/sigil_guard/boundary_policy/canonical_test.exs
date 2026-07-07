defmodule SigilGuard.BoundaryPolicy.CanonicalTest do
  use ExUnit.Case, async: true

  alias SigilGuard.BoundaryPolicy.File, as: PolicyFile
  alias SigilGuard.BoundaryPolicyFixture

  test "the canonical policy parses to the committed expected.json byte-for-byte" do
    committed = File.read!(BoundaryPolicyFixture.expected_path())
    assert BoundaryPolicyFixture.expected_json() == committed
  end

  test "policy_file_digest is the raw-bytes SHA-256, matching sha256sum" do
    bytes = File.read!(BoundaryPolicyFixture.canonical_path())
    expected = Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

    assert PolicyFile.digest(bytes) == expected
    assert {:ok, compiled} = PolicyFile.parse(bytes)
    assert compiled.digest == expected
  end

  test "the digest is over raw bytes with no normalization" do
    trailing = File.read!(BoundaryPolicyFixture.canonical_path()) <> "\n"

    refute PolicyFile.digest(trailing) ==
             PolicyFile.digest(File.read!(BoundaryPolicyFixture.canonical_path()))
  end

  test "the canonical policy encodes the lethal-trifecta rules" do
    {:ok, compiled} = PolicyFile.parse(File.read!(BoundaryPolicyFixture.canonical_path()))
    assert compiled.default == :allow

    [trifecta_block | _] = compiled.rules
    assert trifecta_block.decision == :block

    assert trifecta_block.matchers == %{
             "sensitivity" => ["private"],
             "origin" => ["tool", "resource", "repo"],
             "zone" => ["untrusted"],
             "sink" => ["external", "network"],
             "trust" => ["low", "medium"]
           }
  end
end
