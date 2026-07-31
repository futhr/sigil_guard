defmodule SigilGuard.Attestation.AgentPredicateTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Attestation.AgentPredicate

  @card_digest String.duplicate("c", 64)
  @request_action_digest String.duplicate("a", 64)

  describe "build_request/2" do
    test "builds agent_request extension fields with an optional delegation chain" do
      payload = request_payload()

      assert {:ok, extension} =
               AgentPredicate.build_request(payload,
                 card_digest: @card_digest,
                 peer_trust: :medium,
                 verdict: :allow
               )

      assert extension == %{
               "peer_agent" => %{
                 "id" => "spiffe://agents/responder",
                 "card_digest" => @card_digest
               },
               "peer_trust" => "medium",
               "capability" => "summarize",
               "delegation_chain" => [
                 %{"actor" => "spiffe://agents/router", "evidence" => "audit:1"},
                 %{"actor" => "spiffe://agents/user-proxy"}
               ]
             }
    end

    test "requires quarantine or block when no card digest is bound" do
      assert {:error, :invalid_payload} =
               AgentPredicate.build_request(request_payload(), peer_trust: :low, verdict: :allow)

      assert {:ok, extension} =
               AgentPredicate.build_request(request_payload(),
                 peer_trust: :low,
                 verdict: :quarantine
               )

      refute Map.has_key?(extension["peer_agent"], "card_digest")

      assert {:ok, extension} =
               AgentPredicate.build_request(request_payload(),
                 peer_trust: :low,
                 verdict: :block
               )

      refute Map.has_key?(extension["peer_agent"], "card_digest")
    end

    test "rejects malformed request payloads and delegation chains" do
      assert AgentPredicate.build_request("bad", []) == {:error, :invalid_payload}

      assert {:error, :invalid_payload} =
               AgentPredicate.build_request(%{"capability" => "summarize"},
                 peer_trust: :low,
                 verdict: :quarantine
               )

      assert {:error, :invalid_payload} =
               request_payload()
               |> put_in(["delegation_chain"], [])
               |> AgentPredicate.build_request(peer_trust: :low, verdict: :quarantine)

      assert {:error, :invalid_payload} =
               request_payload()
               |> put_in(["delegation_chain"], [%{"actor" => "agent", "extra" => "nope"}])
               |> AgentPredicate.build_request(peer_trust: :low, verdict: :quarantine)

      assert {:error, :invalid_payload} =
               request_payload()
               |> put_in(["delegation_chain"], [%{"actor" => ""}])
               |> AgentPredicate.build_request(peer_trust: :low, verdict: :quarantine)

      assert {:error, :invalid_payload} =
               request_payload()
               |> put_in(["delegation_chain"], ["bad-hop"])
               |> AgentPredicate.build_request(peer_trust: :low, verdict: :quarantine)

      assert {:error, :invalid_payload} =
               AgentPredicate.build_request(request_payload(),
                 card_digest: String.upcase(@card_digest),
                 peer_trust: :low,
                 verdict: :quarantine
               )

      assert {:error, :invalid_payload} =
               AgentPredicate.build_request(request_payload(),
                 card_digest: @card_digest,
                 verdict: :quarantine
               )
    end

    test "accepts atom-key request payloads" do
      payload = %{
        peer_agent: "spiffe://agents/responder",
        capability: "summarize",
        delegation_chain: [
          %{actor: "spiffe://agents/router", evidence: "audit:1"},
          %{actor: "spiffe://agents/user-proxy"}
        ]
      }

      assert {:ok, extension} =
               AgentPredicate.build_request(payload,
                 peer_trust: :medium,
                 verdict: :quarantine
               )

      assert extension["capability"] == "summarize"

      assert extension["delegation_chain"] == [
               %{"actor" => "spiffe://agents/router", "evidence" => "audit:1"},
               %{"actor" => "spiffe://agents/user-proxy"}
             ]
    end
  end

  describe "build_response/2" do
    test "builds agent_response extension fields" do
      assert {:ok, extension} =
               AgentPredicate.build_response(response_payload(),
                 card_digest: @card_digest,
                 peer_trust: "high",
                 request_action_digest: @request_action_digest,
                 quarantined: false
               )

      assert extension == %{
               "peer_agent" => %{
                 "id" => "spiffe://agents/responder",
                 "card_digest" => @card_digest
               },
               "peer_trust" => "high",
               "capability" => "summarize",
               "request_action_digest" => @request_action_digest,
               "status" => "ok",
               "quarantined" => false
             }
    end

    test "rejects malformed response fields" do
      assert AgentPredicate.build_response("bad", []) == {:error, :invalid_payload}

      assert {:error, :invalid_payload} =
               response_payload()
               |> put_in(["status"], "pending")
               |> AgentPredicate.build_response(
                 peer_trust: :low,
                 request_action_digest: @request_action_digest,
                 quarantined: false
               )

      assert {:error, :invalid_payload} =
               AgentPredicate.build_response(response_payload(),
                 peer_trust: :low,
                 request_action_digest: String.upcase(@request_action_digest),
                 quarantined: false
               )

      assert {:error, :invalid_payload} =
               response_payload()
               |> put_in(["delegation_chain"], [%{"actor" => "spiffe://agents/router"}])
               |> AgentPredicate.build_response(
                 peer_trust: :low,
                 request_action_digest: @request_action_digest,
                 quarantined: false
               )

      assert {:error, :invalid_payload} =
               AgentPredicate.build_response(response_payload(),
                 peer_trust: :low,
                 request_action_digest: @request_action_digest,
                 quarantined: "false"
               )

      assert {:error, :invalid_payload} =
               AgentPredicate.build_response(response_payload(),
                 request_action_digest: @request_action_digest,
                 quarantined: false
               )

      assert {:error, :invalid_payload} =
               AgentPredicate.build_response(response_payload(),
                 peer_trust: :low,
                 quarantined: false
               )
    end

    test "accepts atom-key response payloads and options" do
      payload = %{
        peer_agent: "spiffe://agents/responder",
        capability: "summarize",
        status: "error"
      }

      assert {:ok, extension} =
               AgentPredicate.build_response(payload,
                 peer_trust: :high,
                 request_action_digest: @request_action_digest,
                 quarantined: true
               )

      assert extension["peer_agent"] == %{"id" => "spiffe://agents/responder"}
      assert extension["peer_trust"] == "high"
      assert extension["status"] == "error"
      assert extension["quarantined"] == true
    end
  end

  describe "validate/2" do
    test "accepts valid request and response predicates" do
      assert {:ok, request} =
               AgentPredicate.build_request(request_payload(),
                 peer_trust: :medium,
                 verdict: :quarantine
               )

      assert :ok = AgentPredicate.validate(:agent_request, Map.put(request, "verdict", "block"))

      assert {:ok, response} =
               AgentPredicate.build_response(response_payload(),
                 card_digest: @card_digest,
                 peer_trust: :medium,
                 request_action_digest: @request_action_digest,
                 quarantined: true
               )

      assert :ok = AgentPredicate.validate(:agent_response, response)
    end

    test "accepts atom-key request and response predicates" do
      request = %{
        peer_agent: %{id: "spiffe://agents/responder", card_digest: @card_digest},
        peer_trust: "medium",
        capability: "summarize",
        verdict: "allow"
      }

      assert :ok = AgentPredicate.validate(:agent_request, request)

      response = %{
        peer_agent: %{id: "spiffe://agents/responder", card_digest: @card_digest},
        peer_trust: "medium",
        capability: "summarize",
        request_action_digest: @request_action_digest,
        status: "ok",
        quarantined: false
      }

      assert :ok = AgentPredicate.validate(:agent_response, response)
    end

    test "rejects tool fields on both A2A predicate types" do
      assert {:ok, request} =
               AgentPredicate.build_request(request_payload(),
                 card_digest: @card_digest,
                 peer_trust: :medium,
                 verdict: :allow
               )

      assert {:error, :invalid_payload} =
               :agent_request
               |> AgentPredicate.validate(Map.put(request, "tool", %{"name" => "forbidden"}))

      assert {:ok, response} =
               AgentPredicate.build_response(response_payload(),
                 card_digest: @card_digest,
                 peer_trust: :medium,
                 request_action_digest: @request_action_digest,
                 quarantined: false
               )

      assert {:error, :invalid_payload} =
               :agent_response
               |> AgentPredicate.validate(Map.put(response, "tool", %{"name" => "forbidden"}))
    end

    test "rejects malformed request and response predicates" do
      assert AgentPredicate.validate(:unknown, %{}) == {:error, :invalid_payload}
      assert AgentPredicate.validate(:agent_request, "bad") == {:error, :invalid_payload}

      assert {:error, :invalid_payload} =
               AgentPredicate.validate(:agent_request, %{
                 "peer_agent" => "bad",
                 "peer_trust" => "medium",
                 "capability" => "summarize",
                 "verdict" => "allow"
               })

      assert {:error, :invalid_payload} =
               AgentPredicate.validate(:agent_request, %{
                 "peer_agent" => %{"id" => "spiffe://agents/responder"},
                 "peer_trust" => "unknown",
                 "capability" => "summarize",
                 "verdict" => "quarantine"
               })

      assert {:error, :invalid_payload} =
               AgentPredicate.validate(:agent_response, %{
                 "peer_agent" => %{
                   "id" => "spiffe://agents/responder",
                   "card_digest" => @card_digest
                 },
                 "peer_trust" => "medium",
                 "capability" => "summarize",
                 "request_action_digest" => @request_action_digest,
                 "status" => "ok",
                 "quarantined" => false,
                 "delegation_chain" => []
               })
    end
  end

  describe "action_digest/3" do
    test "uses the attestation agent_request action preimage row" do
      assert AgentPredicate.action_preimage(:agent_request, request_payload(), []) ==
               {:ok,
                %{
                  "statement_type" => "agent_request",
                  "peer_agent" => "spiffe://agents/responder",
                  "capability" => "summarize",
                  "arguments" => %{"topic" => "build"}
                }}

      assert {:ok, digest} = AgentPredicate.action_digest(:agent_request, request_payload(), [])
      assert byte_size(digest) == 64

      assert AgentPredicate.action_preimage(
               :agent_request,
               Map.delete(request_payload(), "arguments"),
               []
             ) ==
               {:ok,
                %{
                  "statement_type" => "agent_request",
                  "peer_agent" => "spiffe://agents/responder",
                  "capability" => "summarize"
                }}
    end

    test "uses the attestation agent_response action preimage row" do
      assert AgentPredicate.action_preimage(:agent_response, response_payload(),
               request_action_digest: @request_action_digest
             ) ==
               {:ok,
                %{
                  "statement_type" => "agent_response",
                  "peer_agent" => "spiffe://agents/responder",
                  "capability" => "summarize",
                  "request_action_digest" => @request_action_digest
                }}

      assert {:ok, digest} =
               AgentPredicate.action_digest(:agent_response, response_payload(),
                 request_action_digest: @request_action_digest
               )

      assert byte_size(digest) == 64
    end

    test "rejects malformed action rows" do
      assert AgentPredicate.action_preimage(:agent_request, "bad", []) ==
               {:error, :invalid_payload}

      assert AgentPredicate.action_preimage(:agent_response, response_payload(), []) ==
               {:error, :invalid_payload}

      assert AgentPredicate.action_preimage(:unknown, %{}, []) == {:error, :invalid_payload}
      assert AgentPredicate.action_digest(:unknown, %{}, []) == {:error, :invalid_payload}

      assert AgentPredicate.action_preimage(
               :agent_request,
               %{
                 peer_agent: "spiffe://agents/responder",
                 capability: "summarize",
                 arguments: nil
               },
               []
             ) ==
               {:ok,
                %{
                  "statement_type" => "agent_request",
                  "peer_agent" => "spiffe://agents/responder",
                  "capability" => "summarize"
                }}
    end
  end

  describe "delegation_chain_digest/1" do
    test "changes when the delegation chain is reordered, inserted, dropped, or edited" do
      payload = request_payload()

      assert {:ok, original} = AgentPredicate.delegation_chain_digest(payload)

      variants = [
        update_in(payload, ["delegation_chain"], &Enum.reverse/1),
        update_in(payload, ["delegation_chain"], fn chain ->
          [%{"actor" => "spiffe://agents/extra"} | chain]
        end),
        update_in(payload, ["delegation_chain"], &tl/1),
        put_in(payload, ["delegation_chain", Access.at(0), "actor"], "spiffe://agents/edited")
      ]

      for variant <- variants do
        assert {:ok, digest} = AgentPredicate.delegation_chain_digest(variant)
        refute digest == original
      end
    end

    test "rejects malformed delegation-chain payloads" do
      assert AgentPredicate.delegation_chain_digest("bad") == {:error, :invalid_payload}

      assert AgentPredicate.delegation_chain_digest(%{
               "delegation_chain" => [%{"actor" => "spiffe://agents/router"}, "bad-hop"]
             }) == {:error, :invalid_payload}
    end
  end

  defp request_payload do
    %{
      "peer_agent" => "spiffe://agents/responder",
      "capability" => "summarize",
      "arguments" => %{"topic" => "build"},
      "delegation_chain" => [
        %{"actor" => "spiffe://agents/router", "evidence" => "audit:1"},
        %{"actor" => "spiffe://agents/user-proxy"}
      ]
    }
  end

  defp response_payload do
    %{
      "peer_agent" => "spiffe://agents/responder",
      "capability" => "summarize",
      "status" => "ok",
      "result" => %{"summary" => "done"}
    }
  end
end
