defmodule SigilGuard.AttestationFromDecisionTest do
  use ExUnit.Case, async: true

  alias SigilGuard.Attestation
  alias SigilGuard.Context
  alias SigilGuard.Decision
  alias SigilGuard.TrustProfile

  @now ~U[2026-07-03 12:00:00.000Z]
  @payload %{"method" => "tools/call", "params" => %{"name" => "repo_file_write"}}
  @context %Context{
    phase: :tool_request,
    actor: "spiffe://agents/requester",
    identity: "fallback-identity",
    trust_level: :medium,
    origin: :user,
    sink: :tool,
    tool: "repo_file_write"
  }

  describe "from_decision/3" do
    test "builds a profile-valid statement from a tool-request decision" do
      assert {:ok, statement} =
               Attestation.from_decision(decision(), @context,
                 payload: @payload,
                 now: @now,
                 ttl_ms: 60_000,
                 nonce: "nonce-1"
               )

      assert TrustProfile.validate(statement) == {:ok, statement}
      assert statement["predicateType"] == "https://sigilguard.dev/attestation/tool_request/v1"
      assert get_in(statement, ["predicate", "actor", "id"]) == @context.actor
      assert get_in(statement, ["predicate", "actor", "trust_level"]) == "medium"
      assert get_in(statement, ["predicate", "verdict"]) == "allow"
      assert get_in(statement, ["predicate", "issued_at"]) == DateTime.to_iso8601(@now)
      assert get_in(statement, ["predicate", "expires_at"]) == "2026-07-03T12:01:00.000Z"
      assert get_in(statement, ["predicate", "nonce"]) == "nonce-1"
      assert subject_names(statement) == ["action", "payload", "context"]
    end

    test "adds tool request resource mirrors from map contexts and string scopes" do
      context = %{
        phase: :tool_request,
        actor: "spiffe://agents/requester",
        trust_level: :medium,
        origin: :model,
        sink: :tool,
        tool: "repo_file_write",
        mcp_server: "repo-mcp",
        resource_uri: "mcp://repo-mcp"
      }

      assert {:ok, statement} =
               Attestation.from_decision(
                 decision(verdict: {:confirm, "review"}, action: :confirm),
                 context,
                 payload: @payload,
                 statement_type: "tool_request",
                 now: @now,
                 manifest_digest: String.duplicate("d", 64),
                 audience: "repo-mcp",
                 scopes: "repo:write"
               )

      predicate = statement["predicate"]
      assert predicate["verdict"] == "confirm"

      assert predicate["tool"] == %{
               "name" => "repo_file_write",
               "mcp_server" => "repo-mcp",
               "manifest_digest" => String.duplicate("d", 64)
             }

      assert predicate["resource"] == %{
               "uri" => "mcp://repo-mcp",
               "audience" => "repo-mcp",
               "scope" => "repo:write"
             }
    end

    test "adds released sanitized result status from explicit result opts" do
      context = %{
        phase: :tool_result,
        actor: "spiffe://agents/requester",
        trust_level: :medium,
        origin: :tool,
        sink: :model,
        tool: "repo_file_write"
      }

      assert {:ok, statement} =
               Attestation.from_decision(decision(action: :redact, phase: :tool_result), context,
                 payload: @payload,
                 now: @now,
                 request_action_digest: String.duplicate("a", 64),
                 quarantine_status: :released_sanitized,
                 indicator_ids: ["z", :ignored, "a"],
                 scanner_hit_count: 2
               )

      assert statement["predicate"]["quarantine"] == %{
               "status" => "released_sanitized",
               "indicator_ids" => ["a", "z"]
             }

      assert statement["predicate"]["scanner"] == %{"hit_count" => 2, "redacted" => true}
    end

    test "builds result predicates from decision fallback metadata" do
      context = [
        phase: :tool_result,
        actor: "spiffe://agents/requester",
        trust_level: :medium,
        origin: :tool,
        sink: :model,
        tool: "repo_file_write"
      ]

      decision =
        decision(action: :allow, phase: :tool_result)
        |> Map.put(:hits, [%{name: "secret"}])
        |> Map.put(:indicators, [%{"id" => "detected-indicator"}])

      assert {:ok, statement} =
               Attestation.from_decision(decision, context,
                 payload: @payload,
                 now: @now,
                 request_action_digest: String.duplicate("b", 64),
                 output_schema_sha256: nil
               )

      predicate = statement["predicate"]
      refute Map.has_key?(predicate, "output_schema_sha256")

      assert predicate["quarantine"] == %{
               "status" => "none",
               "indicator_ids" => ["detected-indicator"]
             }

      assert predicate["scanner"] == %{"hit_count" => 1, "redacted" => false}
    end

    test "omits empty tool request mirrors" do
      context = %{@context | tool: nil, mcp_server: nil, resource_uri: nil}

      assert {:ok, statement} =
               Attestation.from_decision(decision(), context,
                 payload: @payload,
                 now: @now,
                 scopes: []
               )

      predicate = statement["predicate"]
      refute Map.has_key?(predicate, "tool")
      assert predicate["resource"] == %{"audience" => :internal}
    end

    test "explicit statement type wins over phase-derived type" do
      payload = %{"repository" => "repo", "operation" => "write", "paths" => ["b.ex", "a.ex"]}

      assert {:ok, statement} =
               Attestation.from_decision(decision(), @context,
                 payload: payload,
                 statement_type: :repo_change,
                 now: @now
               )

      assert statement["predicateType"] == "https://sigilguard.dev/attestation/repo_change/v1"
      assert get_in(statement, ["predicate", "statement_type"]) == "repo_change"
    end

    test "falls back from context actor to identity" do
      context = %{@context | actor: nil, identity: "spiffe://agents/fallback"}

      assert {:ok, statement} =
               Attestation.from_decision(decision(), context, payload: @payload, now: @now)

      assert get_in(statement, ["predicate", "actor", "id"]) == "spiffe://agents/fallback"
    end

    test "requires explicit statement type for unphased attestation types" do
      payload = %{
        "package" => "sigil_guard",
        "version" => "1.0.0",
        "artifacts" => [
          %{"name" => "sigil_guard-1.0.0.tar", "sha256" => String.duplicate("a", 64)}
        ]
      }

      assert {:ok, statement} =
               Attestation.from_decision(decision(), @context,
                 payload: payload,
                 statement_type: "release",
                 now: @now
               )

      assert statement["predicateType"] == "https://sigilguard.dev/attestation/release/v1"
    end

    test "supports agent request extension fields" do
      payload = %{"peer_agent" => "spiffe://agents/responder", "capability" => "summarize"}
      context = %{@context | phase: :tool_request, trust_level: :low}
      decision = decision(action: :quarantine)

      assert {:ok, statement} =
               Attestation.from_decision(decision, context,
                 payload: payload,
                 statement_type: :agent_request,
                 now: @now,
                 peer_trust: :low
               )

      predicate = statement["predicate"]
      assert predicate["statement_type"] == "agent_request"
      assert predicate["verdict"] == "quarantine"
      assert predicate["peer_agent"] == %{"id" => "spiffe://agents/responder"}
      assert predicate["peer_trust"] == "low"
      assert predicate["capability"] == "summarize"
    end

    test "supports agent response extension fields" do
      payload = %{
        "peer_agent" => "spiffe://agents/responder",
        "capability" => "summarize",
        "status" => "error"
      }

      assert {:ok, statement} =
               Attestation.from_decision(decision(action: :quarantine), @context,
                 payload: payload,
                 statement_type: :agent_response,
                 now: @now,
                 request_action_digest: String.duplicate("a", 64),
                 peer_trust: :medium
               )

      predicate = statement["predicate"]
      assert predicate["statement_type"] == "agent_response"
      assert predicate["status"] == "error"
      assert predicate["request_action_digest"] == String.duplicate("a", 64)
      assert predicate["quarantined"] == true
    end

    test "maps blocked and confirmation decisions into predicate verdicts" do
      for {decision, verdict} <- [
            {decision(verdict: :blocked, action: :block), "block"},
            {decision(verdict: {:confirm, "token"}, action: :confirm), "confirm"}
          ] do
        assert {:ok, statement} =
                 Attestation.from_decision(decision, @context,
                   payload: @payload,
                   now: @now
                 )

        assert get_in(statement, ["predicate", "verdict"]) == verdict
      end
    end

    test "rejects malformed inputs" do
      assert Attestation.from_decision(%{}, @context, payload: @payload, now: @now) ==
               {:error, :invalid_payload}

      assert Attestation.from_decision(decision(), @context, :bad_opts) ==
               {:error, :invalid_payload}

      assert Attestation.from_decision(decision(), @context, now: @now) ==
               {:error, :invalid_payload}

      assert Attestation.from_decision(decision(), @context, payload: "bad", now: @now) ==
               {:error, :invalid_payload}

      assert Attestation.from_decision(decision(), %{@context | actor: nil, identity: nil},
               payload: @payload,
               now: @now
             ) == {:error, :invalid_payload}

      assert Attestation.from_decision(decision(), %{@context | phase: :release},
               payload: @payload,
               now: @now
             ) == {:error, :invalid_phase}

      assert Attestation.from_decision(decision(), "bad", payload: @payload, now: @now) ==
               {:error, :invalid_context}

      assert Attestation.from_decision(decision(), @context,
               payload: @payload,
               statement_type: :unknown,
               now: @now
             ) == {:error, :unknown_statement_type}

      assert Attestation.from_decision(decision(), @context,
               payload: @payload,
               statement_type: 42,
               now: @now
             ) == {:error, :unknown_statement_type}

      assert Attestation.from_decision(decision(), @context,
               payload: @payload,
               now: "bad-now"
             ) == {:error, :invalid_payload}

      assert Attestation.from_decision(decision(), @context,
               payload: @payload,
               now: @now,
               ttl_ms: 0
             ) ==
               {:error, :invalid_payload}

      result_context = %{@context | phase: :tool_result, origin: :tool, sink: :model}

      assert Attestation.from_decision(decision(phase: :tool_result), result_context,
               payload: @payload,
               now: @now,
               request_action_digest: "bad"
             ) == {:error, :invalid_payload}

      assert Attestation.from_decision(decision(phase: :tool_result), result_context,
               payload: @payload,
               now: @now,
               request_action_digest: String.duplicate("c", 64),
               output_schema_sha256: :bad
             ) == {:error, :invalid_payload}

      assert Attestation.from_decision(decision(phase: :tool_result), result_context,
               payload: @payload,
               now: @now,
               request_action_digest: String.duplicate("c", 64),
               redacted: :bad
             ) == {:error, :invalid_payload}
    end
  end

  defp decision(overrides \\ []) do
    attrs =
      Keyword.merge(
        [
          verdict: :allowed,
          action: :allow,
          phase: :tool_request,
          risk_level: :low,
          trust_level: :medium
        ],
        overrides
      )

    struct!(Decision, attrs)
  end

  defp subject_names(statement) do
    Enum.map(statement["subject"], & &1["name"])
  end
end
