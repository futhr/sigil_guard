defmodule SigilGuard.TrustProfileTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Attestation.AgentPredicate
  alias SigilGuard.Attestation.Statement
  alias SigilGuard.TrustProfile

  @statement_types [
    :tool_request,
    :tool_result,
    :model_ingress,
    :model_egress,
    :repo_change,
    :release,
    :agent_request,
    :agent_response
  ]

  @digest_a String.duplicate("a", 64)
  @digest_b String.duplicate("b", 64)
  @digest_c String.duplicate("c", 64)
  @request_action_digest String.duplicate("d", 64)

  describe "profile_id/0" do
    test "returns the v1 agent trust profile id" do
      assert TrustProfile.profile_id() == "sigil_guard_agent_trust/v1"
    end
  end

  describe "statement_types/0" do
    test "returns the registered types in fixed order" do
      assert TrustProfile.statement_types() == @statement_types
    end
  end

  describe "predicate_type/1" do
    test "maps registered statement types to closed predicate type URIs" do
      for statement_type <- @statement_types do
        assert TrustProfile.predicate_type(statement_type) ==
                 {:ok, "https://sigilguard.dev/attestation/#{statement_type}/v1"}
      end
    end

    test "rejects unknown statement types" do
      assert TrustProfile.predicate_type(:unknown) == {:error, :unknown_statement_type}
      assert TrustProfile.predicate_type("tool_request") == {:error, :unknown_statement_type}
    end
  end

  describe "validate/1" do
    test "validates all registered statement types" do
      for statement_type <- @statement_types do
        assert {:ok, statement} = valid_statement(statement_type)
        assert TrustProfile.validate(statement) == {:ok, statement}
      end
    end

    test "rejects malformed statement shape as invalid profile" do
      assert {:ok, statement} = valid_statement(:tool_request)

      assert statement
             |> put_in(["subject"], Enum.reverse(statement["subject"]))
             |> TrustProfile.validate() == {:error, :invalid_profile}
    end

    test "rejects unregistered predicate types" do
      assert {:ok, statement} = valid_statement(:tool_request)

      assert statement
             |> put_in(["predicateType"], "https://sigilguard.dev/attestation/unknown/v1")
             |> TrustProfile.validate() == {:error, :unknown_statement_type}
    end

    test "rejects unsupported profile versions by stem" do
      assert {:ok, statement} = valid_statement(:tool_request)

      assert statement
             |> put_in(["predicate", "profile"], "sigil_guard_agent_trust/v2")
             |> TrustProfile.validate() == {:error, :unsupported_profile_version}
    end

    test "rejects unknown profile stems as invalid profile" do
      assert {:ok, statement} = valid_statement(:tool_request)

      assert statement
             |> put_in(["predicate", "profile"], "other_profile/v1")
             |> TrustProfile.validate() == {:error, :invalid_profile}

      assert statement
             |> put_in(["predicate", "profile"], :sigil_guard_agent_trust)
             |> TrustProfile.validate() == {:error, :invalid_profile}
    end

    test "rejects statement type field mismatch as unknown statement type" do
      assert {:ok, statement} = valid_statement(:tool_request)

      assert statement
             |> put_in(["predicate", "statement_type"], "tool_result")
             |> TrustProfile.validate() == {:error, :unknown_statement_type}
    end

    test "rejects missing or malformed statement type fields as invalid payload" do
      assert {:ok, statement} = valid_statement(:tool_request)

      assert statement
             |> update_in(["predicate"], &Map.delete(&1, "statement_type"))
             |> TrustProfile.validate() == {:error, :invalid_payload}

      assert statement
             |> put_in(["predicate", "statement_type"], :tool_request)
             |> TrustProfile.validate() == {:error, :invalid_payload}
    end

    test "rejects malformed A2A predicate extensions" do
      assert {:ok, request_statement} = valid_statement(:agent_request)

      assert request_statement
             |> put_in(["predicate", "tool"], %{"name" => "forbidden"})
             |> TrustProfile.validate() == {:error, :invalid_payload}

      assert {:ok, response_statement} = valid_statement(:agent_response)

      assert response_statement
             |> put_in(["predicate", "delegation_chain"], [%{"actor" => "agent"}])
             |> TrustProfile.validate() == {:error, :invalid_payload}
    end
  end

  defp valid_statement(statement_type) do
    {:ok, predicate_type} = TrustProfile.predicate_type(statement_type)

    Statement.build(predicate_type, predicate(statement_type), %{
      action: @digest_a,
      payload: @digest_b,
      context: @digest_c
    })
  end

  defp predicate(statement_type) do
    statement_type
    |> base_predicate()
    |> Map.merge(predicate_extension(statement_type))
  end

  defp base_predicate(statement_type) do
    %{
      "profile" => TrustProfile.profile_id(),
      "statement_type" => Atom.to_string(statement_type),
      "verdict" => "quarantine"
    }
  end

  defp predicate_extension(:agent_request) do
    {:ok, extension} =
      AgentPredicate.build_request(agent_request_payload(),
        peer_trust: :low,
        verdict: :quarantine
      )

    extension
  end

  defp predicate_extension(:agent_response) do
    {:ok, extension} =
      AgentPredicate.build_response(agent_response_payload(),
        peer_trust: :low,
        request_action_digest: @request_action_digest,
        quarantined: false
      )

    extension
  end

  defp predicate_extension(_), do: %{}

  defp agent_request_payload do
    %{
      "peer_agent" => "spiffe://agents/responder",
      "capability" => "summarize",
      "arguments" => %{"topic" => "build"}
    }
  end

  defp agent_response_payload do
    %{
      "peer_agent" => "spiffe://agents/responder",
      "capability" => "summarize",
      "status" => "ok"
    }
  end
end
