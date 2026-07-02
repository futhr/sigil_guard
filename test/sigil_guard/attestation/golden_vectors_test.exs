defmodule SigilGuard.Attestation.GoldenVectorsTest do
  use ExUnit.Case, async: true

  alias SigilGuard.AgentTrustFixtureGenerator
  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Canonical.JCS

  @fixture_root Path.expand("../../fixtures/agent_trust", __DIR__)
  @files ~w(statement.json envelope.json expected.json)

  test "agent-trust fixtures regenerate byte-identically" do
    tmp_root =
      Path.join(System.tmp_dir!(), "sigil-agent-trust-fixtures-#{System.unique_integer()}")

    try do
      AgentTrustFixtureGenerator.write!(tmp_root)

      for type <- AgentTrustFixtureGenerator.types(), file <- @files do
        fixture = Path.join([@fixture_root, Atom.to_string(type), file])
        regenerated = Path.join([tmp_root, Atom.to_string(type), file])

        assert File.read!(regenerated) == File.read!(fixture)
      end
    after
      File.rm_rf!(tmp_root)
    end
  end

  test "each vector statement and envelope verifies against expected values" do
    for type <- AgentTrustFixtureGenerator.types() do
      dir = Path.join(@fixture_root, Atom.to_string(type))
      statement_json = File.read!(Path.join(dir, "statement.json"))
      envelope_json = File.read!(Path.join(dir, "envelope.json"))
      expected = decode_file!(Path.join(dir, "expected.json"))
      envelope = Jason.decode!(envelope_json)

      keyid = expected["keyid"]
      public_key = Base.decode16!(expected["public_key_hex"], case: :lower)

      assert :crypto.hash(:sha256, statement_json) |> Base.encode16(case: :lower) ==
               expected["statement_sha256"]

      assert Envelope.keyid(public_key) == keyid
      assert Envelope.verify(envelope, %{keyid => public_key}) == {:ok, statement_json}

      assert Base.url_decode64!(envelope["payload"], padding: false) == statement_json
      assert envelope["signatures"] == [%{"keyid" => keyid, "sig" => expected["signature"]}]

      assert :crypto.hash(:sha256, Envelope.pae(Envelope.payload_type(), statement_json))
             |> Base.encode16(case: :lower) == expected["pae_sha256"]
    end
  end

  test "tool_request vector carries the worked-example manifest digest" do
    dir = Path.join(@fixture_root, "tool_request")
    statement = decode_file!(Path.join(dir, "statement.json"))
    expected = decode_file!(Path.join(dir, "expected.json"))

    assert get_in(statement, ["predicate", "tool", "name"]) == "repo_file_write"
    assert get_in(statement, ["predicate", "tool", "mcp_server"]) == "repo-mcp"

    assert get_in(statement, ["predicate", "tool", "manifest_digest"]) ==
             expected["manifest_digest"]

    assert Enum.find(statement["subject"], &(&1["name"] == "manifest")) ==
             %{"name" => "manifest", "digest" => %{"sha256" => expected["manifest_digest"]}}
  end

  test "fixtures are compact JCS bytes" do
    for type <- AgentTrustFixtureGenerator.types(), file <- @files do
      bytes = File.read!(Path.join([@fixture_root, Atom.to_string(type), file]))
      decoded = Jason.decode!(bytes)

      assert {:ok, ^bytes} = JCS.encode(decoded)
      refute String.contains?(bytes, "\n")
    end
  end

  defp decode_file!(path) do
    path
    |> File.read!()
    |> Jason.decode!()
  end
end
