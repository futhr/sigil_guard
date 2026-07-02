defmodule SigilGuard.Attestation.DigestTest do
  use ExUnit.Case, async: true

  alias SigilGuard.Attestation
  alias SigilGuard.Attestation.Digest
  alias SigilGuard.Canonical.JCS

  @request_action_digest String.duplicate("a", 64)
  @manifest_digest String.duplicate("b", 64)

  describe "normalize/1" do
    test "converts atom keys and values, omits nil map entries, and preserves booleans" do
      assert Digest.normalize(%{
               phase: :tool_request,
               skipped: nil,
               nested: %{allow?: true, trust: :low},
               list: [:agent_request, nil, false]
             }) ==
               {:ok,
                %{
                  "phase" => "tool_request",
                  "nested" => %{"allow?" => true, "trust" => "low"},
                  "list" => ["agent_request", nil, false]
                }}
    end

    test "rejects normalized key collisions and invalid values" do
      assert Digest.normalize(%{:phase => :tool_request, "phase" => "tool_request"}) ==
               {:error, :invalid_payload}

      assert Digest.normalize(%{"bad" => self()}) == {:error, :invalid_payload}
    end
  end

  describe "payload_digest/1" do
    test "hashes UTF-8 binary payload bytes directly" do
      assert Digest.payload_digest("payload") == {:ok, sha256("payload")}
    end

    test "hashes stripped normalized maps and lists" do
      payload = %{
        "name" => "repo_file_write",
        "params" => %{"arguments" => %{"path" => "README.md"}},
        "_agent_trust" => %{"payload" => "ignored"},
        confirmation_token: "ignored"
      }

      stripped = Attestation.strip_metadata(payload)
      assert {:ok, canonical} = JCS.encode(stripped)
      assert Digest.payload_digest(payload) == {:ok, sha256(canonical)}

      list_payload = [payload, %{"_agent_confirmation" => "ignored", "value" => true}]
      stripped_list = Attestation.strip_metadata(list_payload)
      assert {:ok, canonical_list} = JCS.encode(stripped_list)
      assert Digest.payload_digest(list_payload) == {:ok, sha256(canonical_list)}
    end

    test "rejects malformed payload classes" do
      assert Digest.payload_digest({:bad}) == {:error, :invalid_payload}
      assert Digest.payload_digest(<<255>>) == {:error, :invalid_payload}
      assert Digest.payload_digest(%{1 => "bad-key"}) == {:error, :invalid_payload}
    end
  end

  describe "context_digest/2" do
    test "includes sandbox_id and isolation_level when present" do
      context = %{
        phase: :tool_request,
        origin: :user,
        sink: :tool,
        trust_zone: :untrusted,
        intended_audience: :tool,
        sandbox_id: "sbx-1",
        isolation_level: "strict"
      }

      assert Digest.context_preimage(:tool_request, context) ==
               {:ok,
                %{
                  "statement_type" => "tool_request",
                  "trust_level" => :low,
                  "phase" => :tool_request,
                  "origin" => :user,
                  "sink" => :tool,
                  "trust_zone" => :untrusted,
                  "intended_audience" => :tool,
                  "sandbox_id" => "sbx-1",
                  "isolation_level" => "strict"
                }}

      assert {:ok, without_sandbox} =
               Digest.context_digest(:tool_request, Map.drop(context, [:sandbox_id]))

      assert {:ok, with_sandbox} = Digest.context_digest(:tool_request, context)
      refute with_sandbox == without_sandbox
    end
  end

  describe "action_preimage/4" do
    test "builds tool_request and tool_result rows" do
      request_payload = %{
        "method" => "tools/call",
        "params" => %{
          "name" => "repo_file_write",
          "arguments" => %{"path" => "README.md", "_agent_trust" => %{}}
        }
      }

      assert Digest.action_preimage(:tool_request, request_payload, %{phase: :tool_request}, []) ==
               {:ok,
                %{
                  "statement_type" => "tool_request",
                  "tool" => "repo_file_write",
                  "method" => "tools/call",
                  "arguments" => %{"path" => "README.md"}
                }}

      assert Digest.action_preimage(
               :tool_result,
               %{"method" => "tools/call"},
               %{phase: :tool_result, tool: "repo_file_write"},
               request_action_digest: @request_action_digest
             ) ==
               {:ok,
                %{
                  "statement_type" => "tool_result",
                  "tool" => "repo_file_write",
                  "method" => "tools/call",
                  "request_action_digest" => @request_action_digest
                }}
    end

    test "builds model boundary rows" do
      assert Digest.action_preimage(
               :model_ingress,
               %{},
               %{origin: :user, source: "chat", resource_uri: "memory://1"},
               []
             ) ==
               {:ok,
                %{
                  "statement_type" => "model_ingress",
                  "origin" => "user",
                  "source" => "chat",
                  "resource_uri" => "memory://1"
                }}

      assert Digest.action_preimage(
               :model_egress,
               %{},
               %{sink: :user, intended_audience: :user, resource_uri: "chat://1"},
               []
             ) ==
               {:ok,
                %{
                  "statement_type" => "model_egress",
                  "sink" => "user",
                  "intended_audience" => "user",
                  "resource_uri" => "chat://1"
                }}
    end

    test "builds repo_change and release rows" do
      assert Digest.action_preimage(
               :repo_change,
               %{
                 "repository" => "sigil_guard",
                 "operation" => "write",
                 "paths" => ["lib/z.ex", "README.md"],
                 "ref" => "main"
               },
               %{},
               []
             ) ==
               {:ok,
                %{
                  "statement_type" => "repo_change",
                  "repository" => "sigil_guard",
                  "operation" => "write",
                  "paths" => ["README.md", "lib/z.ex"],
                  "ref" => "main"
                }}

      assert Digest.action_preimage(
               :release,
               %{
                 "package" => "sigil_guard",
                 "version" => "3.0.0",
                 "artifacts" => [
                   %{"name" => "z.tar", "sha256" => String.duplicate("c", 64)},
                   %{name: "a.tar", sha256: String.duplicate("d", 64)}
                 ]
               },
               %{},
               []
             ) ==
               {:ok,
                %{
                  "statement_type" => "release",
                  "package" => "sigil_guard",
                  "version" => "3.0.0",
                  "artifacts" => [
                    %{"name" => "a.tar", "sha256" => String.duplicate("d", 64)},
                    %{"name" => "z.tar", "sha256" => String.duplicate("c", 64)}
                  ]
                }}
    end

    test "builds agent_request and agent_response rows" do
      assert Digest.action_preimage(
               :agent_request,
               %{
                 "peer_agent" => "spiffe://agents/responder",
                 "capability" => "summarize",
                 "arguments" => %{"topic" => "build"}
               },
               %{},
               []
             ) ==
               {:ok,
                %{
                  "statement_type" => "agent_request",
                  "peer_agent" => "spiffe://agents/responder",
                  "capability" => "summarize",
                  "arguments" => %{"topic" => "build"}
                }}

      assert Digest.action_preimage(
               :agent_response,
               %{"peer_agent" => "spiffe://agents/responder", "capability" => "summarize"},
               %{},
               request_action_digest: @request_action_digest
             ) ==
               {:ok,
                %{
                  "statement_type" => "agent_response",
                  "peer_agent" => "spiffe://agents/responder",
                  "capability" => "summarize",
                  "request_action_digest" => @request_action_digest
                }}
    end

    test "rejects malformed action rows" do
      assert Digest.action_preimage(:tool_request, %{}, %{}, []) == {:error, :invalid_payload}

      assert Digest.action_preimage(:repo_change, %{"paths" => [1]}, %{}, []) ==
               {:error, :invalid_payload}

      assert Digest.action_preimage(
               :agent_response,
               %{"peer_agent" => "a", "capability" => "c"},
               %{},
               []
             ) ==
               {:error, :invalid_payload}
    end
  end

  describe "digests/4" do
    test "returns action, payload, context, and applicable manifest digests" do
      payload = %{"name" => "repo_file_write"}
      context = %{phase: :tool_request, origin: :user, sink: :tool, tool: "repo_file_write"}

      assert {:ok, digests} =
               Digest.digests(:tool_request, payload, context, manifest_digest: @manifest_digest)

      assert Map.keys(digests) == ~w(action context manifest payload)
      assert digests["manifest"] == @manifest_digest

      assert {:ok, model_digests} = Digest.digests(:model_ingress, %{}, %{origin: :user}, [])
      refute Map.has_key?(model_digests, "manifest")
    end
  end

  defp sha256(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
end
