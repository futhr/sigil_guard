defmodule SigilGuard.ToolGatewayTest do
  use ExUnit.Case, async: false

  alias SigilGuard.CapabilityManifest
  alias SigilGuard.Confirmation
  alias SigilGuard.Decision
  alias SigilGuard.ReplayStore
  alias SigilGuard.ToolGateway

  @fixture Path.expand("../fixtures/capability_manifest/repo_file_write", __DIR__)
  @confirmation_key :crypto.hash(:sha256, "tool-gateway-confirmation-test-key")
  @now ~U[2026-06-30 12:00:00.000Z]

  setup do
    ReplayStore.clear()
    on_exit(&ReplayStore.clear/0)
    :ok
  end

  describe "guard_request/3" do
    test "delegates to the runtime gate when no manifest is required" do
      decision = ToolGateway.guard_request(request(), trust_level: :high)

      assert %Decision{} = decision
      assert decision.verdict == :allowed
      assert decision.audit_metadata.tool == "repo_file_write"
    end

    test "passes through non-map requests when manifests are optional" do
      decision = ToolGateway.guard_request("plain text request", :bad_context, risk_level: :low)

      assert decision.verdict == :allowed
      assert decision.audit_metadata.tool == nil
    end

    test "normalizes list values in request text before runtime evaluation" do
      decision = ToolGateway.guard_request(request_with_list_argument(), trust_level: :high)

      assert decision.verdict == :allowed
      assert decision.audit_metadata.tool == "repo_file_write"
    end

    test "normalizes non-string values without leaking them into actions" do
      request =
        request()
        |> put_in(["params", "arguments", "content"], ["hello", 123])
        |> Map.put("tool", false)

      decision = ToolGateway.guard_request(request, trust_level: :high)

      assert decision.verdict == :blocked
      assert decision.audit_metadata.runtime_input_error == :invalid_action
      assert decision.audit_metadata.tool == nil
    end

    test "fails closed when required manifests do not resolve" do
      decision =
        ToolGateway.guard_request(request(), [trust_level: :high],
          require_manifest: true,
          manifests: %{}
        )

      assert decision.verdict == :blocked
      assert decision.reason =~ "unknown_manifest"
      assert decision.audit_metadata.deny_reason == :unknown_manifest
      assert decision.audit_metadata.tool == "repo_file_write"
    end

    test "fails closed when the manifest registry is malformed" do
      decision =
        ToolGateway.guard_request(request(), [trust_level: :high],
          require_manifest: true,
          manifests: :bad
        )

      assert decision.verdict == :blocked
      assert decision.audit_metadata.deny_reason == :unknown_manifest
    end

    test "fails closed for unknown tools without creating atom keys" do
      request = put_in(request(), ["params", "name"], "tool_that_was_not_preloaded")

      decision =
        ToolGateway.guard_request(request, [trust_level: :high],
          require_manifest: true,
          manifests: %{repo_file_write: manifest()}
        )

      assert decision.verdict == :blocked
      assert decision.audit_metadata.deny_reason == :unknown_manifest
      assert decision.audit_metadata.tool == "tool_that_was_not_preloaded"
    end

    test "fails closed when a manifest entry is malformed" do
      decision =
        ToolGateway.guard_request(request(), [trust_level: :high],
          require_manifest: true,
          manifests: %{"repo_file_write" => :bad}
        )

      assert decision.verdict == :blocked
      assert decision.audit_metadata.deny_reason == :invalid_manifest
    end

    test "blocks the first manifest verification failure before runtime scanning" do
      observed = Map.put(manifest(), "network_access", "outbound")

      decision =
        ToolGateway.guard_request(request_with_secret(), [trust_level: :high],
          manifests: %{"repo_file_write" => {manifest(), observed}},
          require_manifest: true
        )

      assert decision.verdict == :blocked
      assert decision.reason =~ "manifest_digest_mismatch"
      assert decision.audit_metadata.deny_reason == :manifest_digest_mismatch
      assert decision.audit_metadata.hit_count == 0
      refute inspect(decision.audit_metadata) =~ "AKIAIOSFODNN7EXAMPLE"
    end

    test "accepts atom-keyed normalized manifests" do
      assert {:ok, capability} = CapabilityManifest.new(manifest())

      decision =
        ToolGateway.guard_request(request(), [trust_level: :high],
          manifests: %{repo_file_write: capability},
          require_manifest: true
        )

      assert decision.verdict == :allowed
      assert decision.audit_metadata.manifest_name == "repo_file_write"
      assert decision.audit_metadata.manifest_digest == capability.digest
    end

    test "accepts verified pinned and observed manifest tuples" do
      decision =
        ToolGateway.guard_request(request(), [trust_level: :high],
          manifests: %{"repo_file_write" => {manifest(), manifest()}},
          require_manifest: true
        )

      assert decision.verdict == :allowed
      assert decision.audit_metadata.manifest_name == "repo_file_write"
    end

    test "rejects manifests for a different tool name" do
      decision =
        ToolGateway.guard_request(request(), [trust_level: :high],
          manifests: %{"repo_file_write" => Map.put(manifest(), "name", "other_tool")},
          require_manifest: true
        )

      assert decision.verdict == :blocked
      assert decision.audit_metadata.deny_reason == :manifest_digest_mismatch
    end

    test "forces confirmation for disclosed suspicious required parameters" do
      capability = suspicious_manifest()

      decision =
        ToolGateway.guard_request(request(), [trust_level: :high],
          manifests: %{"repo_file_write" => capability},
          require_manifest: true
        )

      assert {:confirm, "suspicious_required_param"} = decision.verdict
      assert decision.action == :confirm
      assert decision.audit_metadata.deny_reason == :suspicious_required_param
      assert decision.audit_metadata.suspicious_params == ["apiKey"]
      assert decision.audit_metadata.action_digest =~ ~r/^[0-9a-f]{64}$/
      assert decision.audit_metadata.manifest_digest
    end

    test "keeps runtime blocks stronger than suspicious-parameter confirmation" do
      decision =
        ToolGateway.guard_request(request_with_secret(), [trust_level: :high],
          manifests: %{"repo_file_write" => suspicious_manifest()},
          require_manifest: true
        )

      assert decision.verdict == :blocked
      assert decision.audit_metadata.hit_count == 1
      refute decision.audit_metadata[:deny_reason] == :suspicious_required_param
    end

    test "lets boundary policy explicitly allow suspicious required parameters" do
      decision =
        ToolGateway.guard_request(request(), [trust_level: :high],
          manifests: %{"repo_file_write" => suspicious_manifest()},
          require_manifest: true,
          allow_suspicious_params: true
        )

      assert decision.verdict == :allowed
      assert decision.action == :allow
      assert decision.audit_metadata.suspicious_params == ["apiKey"]
    end

    test "applies a confirmation token to a suspicious-parameter decision" do
      opts = [
        manifests: %{"repo_file_write" => suspicious_manifest()},
        require_manifest: true
      ]

      decision = ToolGateway.guard_request(request(), [trust_level: :high], opts)

      assert {:confirm, _} = decision.verdict

      assert {:ok, token} =
               Confirmation.issue(
                 request_payload(),
                 request_context(),
                 decision,
                 @confirmation_key,
                 now: @now,
                 nonce: "tool-gateway-confirmation-nonce"
               )

      confirmed =
        ToolGateway.guard_request(request(), [trust_level: :high],
          manifests: %{"repo_file_write" => suspicious_manifest()},
          require_manifest: true,
          confirmation: token,
          confirmation_key: @confirmation_key,
          consume_confirmation: false,
          now: @now
        )

      assert confirmed.verdict == :allowed
      assert confirmed.reason == "Confirmation token accepted"
      assert confirmed.audit_metadata.confirmation_status == :accepted
    end

    test "blocks malformed confirmation options for suspicious-parameter decisions" do
      decision =
        ToolGateway.guard_request(request(), [trust_level: :high],
          manifests: %{"repo_file_write" => suspicious_manifest()},
          require_manifest: true,
          confirmation: 123
        )

      assert decision.verdict == :blocked
      assert decision.audit_metadata.deny_reason == :confirmation_failed
      assert decision.audit_metadata.confirmation_reason == :invalid_confirmation_token
    end

    test "blocks confirmation tokens without a key" do
      decision =
        ToolGateway.guard_request(request(), [trust_level: :high],
          manifests: %{"repo_file_write" => suspicious_manifest()},
          require_manifest: true,
          confirmation: "bad.token"
        )

      assert decision.verdict == :blocked
      assert decision.audit_metadata.confirmation_reason == :missing_confirmation_key
    end

    test "blocks invalid confirmation tokens with a key" do
      decision =
        ToolGateway.guard_request(request(), [trust_level: :high],
          manifests: %{"repo_file_write" => suspicious_manifest()},
          require_manifest: true,
          confirmation: "bad.token",
          confirmation_key: @confirmation_key
        )

      assert decision.verdict == :blocked
      assert decision.audit_metadata.confirmation_reason == :invalid_token
    end

    test "leaves confirmation-required decisions pending when confirmation is true" do
      decision =
        ToolGateway.guard_request(request(), %{"trust_level" => :high, "unknown" => "ignored"},
          manifests: %{"repo_file_write" => suspicious_manifest()},
          require_manifest: true,
          confirmation: true
        )

      assert {:confirm, "suspicious_required_param"} = decision.verdict
      assert decision.action == :confirm
    end

    test "requires sandboxed manifests for executable tool requests" do
      decision =
        ToolGateway.guard_request(request(), [trust_level: :high],
          manifests: %{
            "repo_file_write" => Map.put(manifest(), "sandbox", %{"required" => false})
          },
          require_manifest: true
        )

      assert decision.verdict == :blocked
      assert decision.audit_metadata.deny_reason == :missing_sandbox
    end
  end

  describe "verify_manifest/2" do
    test "returns normalized manifests from the manifest set" do
      assert {:ok, %CapabilityManifest{} = capability} =
               ToolGateway.verify_manifest("repo_file_write",
                 manifests: %{"repo_file_write" => manifest()}
               )

      assert capability.name == "repo_file_write"
    end

    test "returns named errors for unknown and malformed manifests" do
      assert ToolGateway.verify_manifest("repo_file_write", manifests: %{}) ==
               {:error, :unknown_manifest}

      assert ToolGateway.verify_manifest("repo_file_write",
               manifests: %{"repo_file_write" => Map.delete(manifest(), "server")}
             ) == {:error, :invalid_manifest}

      assert ToolGateway.verify_manifest(:repo_file_write, manifests: %{}) ==
               {:error, :unknown_manifest}
    end
  end

  defp request do
    %{
      "method" => "tools/call",
      "params" => %{
        "name" => "repo_file_write",
        "arguments" => %{"path" => "README.md", "content" => "hello"}
      }
    }
  end

  defp request_with_list_argument do
    put_in(request(), ["params", "arguments", "content"], ["hello", "world"])
  end

  defp request_with_secret do
    put_in(request(), ["params", "arguments", "content"], "AWS_KEY=AKIAIOSFODNN7EXAMPLE")
  end

  defp request_payload do
    %{
      tool: "repo_file_write",
      action: "repo_file_write",
      text: "tools/call\nhello\nREADME.md\nrepo_file_write"
    }
  end

  defp request_context do
    %{
      phase: :tool_request,
      origin: :model,
      sink: :tool,
      tool: "repo_file_write",
      action: "repo_file_write",
      mcp_server: nil,
      trust_level: :high
    }
  end

  defp suspicious_manifest do
    manifest()
    |> put_in(["input_schema", "required"], ["apiKey", "content", "path"])
    |> Map.put("suspicious_params", ["apiKey"])
  end

  defp manifest do
    @fixture
    |> Path.join("manifest.json")
    |> File.read!()
    |> Jason.decode!()
  end
end
