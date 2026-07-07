defmodule SigilGuard.ReleaseNoNetworkSweepTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Attestation
  alias SigilGuard.Audit
  alias SigilGuard.Audit.Anchor
  alias SigilGuard.Audit.Anchor.Store
  alias SigilGuard.Audit.Anchor.Store.LocalFile
  alias SigilGuard.Audit.Checkpoint
  alias SigilGuard.BoundaryPolicy
  alias SigilGuard.Context
  alias SigilGuard.Decision
  alias SigilGuard.Runtime.Gate
  alias SigilGuard.TestSigner
  alias SigilGuard.TrustBundle

  @fixtures SigilGuard.FixturePath.path("trust_bundle")
  @now ~U[2026-07-03 12:00:00.000Z]
  @secret_key :crypto.hash(:sha256, "release no network sweep")

  test "release decision paths do not open ports" do
    assert_unchanged_ports(fn ->
      assert {:ok, "safe text"} = SigilGuard.scan("safe text")
      assert "safe text" = SigilGuard.scan_and_redact("safe text")
    end)

    assert_unchanged_ports(fn ->
      decision =
        BoundaryPolicy.evaluate(
          phase: :tool_result,
          source: :tool,
          sink: :model,
          source_sensitivity: :public,
          trust_level: :medium,
          action_digest: String.duplicate("a", 64),
          payload_digest: String.duplicate("b", 64),
          context_digest: String.duplicate("c", 64)
        )

      assert %Decision{action: :allow} = decision
    end)

    assert_unchanged_ports(fn ->
      decision =
        Gate.evaluate("build completed",
          phase: :tool_result,
          origin: :tool,
          sink: :model,
          tool: "compile",
          trust_level: :medium
        )

      assert %Decision{action: :allow} = decision
    end)

    assert_unchanged_ports(fn ->
      assert {:ok, _} =
               Attestation.from_decision(decision(), context(),
                 payload: %{"method" => "tools/call", "params" => %{"name" => "compile"}},
                 now: @now,
                 ttl_ms: 60_000,
                 nonce: "release-no-network"
               )
    end)

    assert_unchanged_ports(fn ->
      envelope = read_json(["minimal", "envelope.json"])
      assert {:ok, %TrustBundle{}} = TrustBundle.verify(envelope, now: @now, quarantine: false)
    end)

    assert_unchanged_ports(fn ->
      {checkpoint, anchor} = local_anchor_fixture()
      path = tmp_path()

      assert {:ok, receipt} = Store.put(LocalFile, anchor, path: path)
      assert {:ok, ^anchor} = Store.fetch(LocalFile, receipt)
      assert {:ok, _} = Store.verify(LocalFile, receipt, checkpoint)
    end)
  end

  test "core decision paths do not reference socket clients directly" do
    paths =
      ~w[
        lib/sigil_guard.ex
        lib/sigil_guard/attestation.ex
        lib/sigil_guard/attestation
        lib/sigil_guard/boundary_policy.ex
        lib/sigil_guard/boundary_policy
        lib/sigil_guard/runtime
        lib/sigil_guard/scanner.ex
        lib/sigil_guard/scanner
        lib/sigil_guard/trust_bundle.ex
        lib/sigil_guard/trust_bundle
      ]

    contents =
      paths
      |> Enum.flat_map(&source_files/1)
      |> Enum.map_join("\n", &File.read!/1)

    for reference <- [":httpc", ":gen_tcp", ":ssl", "SigilGuard.HTTPClient"] do
      refute contents =~ reference
    end
  end

  defp assert_unchanged_ports(fun) do
    before_ports = current_process_ports()
    fun.()
    assert current_process_ports() == before_ports
  end

  defp current_process_ports do
    owner = self()

    Port.list()
    |> Enum.filter(&(Port.info(&1, :connected) == {:connected, owner}))
    |> MapSet.new()
  end

  defp context do
    %Context{
      phase: :tool_request,
      actor: "spiffe://agents/requester",
      identity: "fallback-identity",
      trust_level: :medium,
      origin: :user,
      sink: :tool,
      tool: "compile"
    }
  end

  defp decision do
    %Decision{
      verdict: :allowed,
      action: :allow,
      phase: :tool_request,
      risk_level: :low,
      trust_level: :medium
    }
  end

  defp local_anchor_fixture do
    events =
      1..3
      |> Enum.map(&Audit.new_event("test", "alice", "release-no-network-#{&1}", "ok"))
      |> Audit.build_chain(@secret_key)

    {:ok, checkpoint} =
      Checkpoint.create(events,
        chain_id: "release-no-network",
        generated_at: "2026-01-01T00:00:00.000Z"
      )

    signed_checkpoint =
      Checkpoint.sign(checkpoint, TestSigner,
        issuer: "did:web:release-no-network.example",
        issued_at: "2026-01-01T00:00:00.000Z"
      )

    anchor =
      Anchor.create(signed_checkpoint,
        anchored_at: "2026-01-01T00:00:05.000Z",
        storage: :local_file,
        uri: "file://anchors.jsonl"
      )

    {signed_checkpoint, anchor}
  end

  defp tmp_path do
    root =
      System.tmp_dir!()
      |> Path.join("sigil_guard_release_no_network_tests")
      |> Path.join("#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf(root) end)

    Path.join(root, "anchors.jsonl")
  end

  defp read_json(path) do
    path
    |> then(&Path.join([@fixtures | &1]))
    |> File.read!()
    |> Jason.decode!()
  end

  defp source_files(path) do
    cond do
      File.regular?(path) -> [path]
      File.dir?(path) -> Path.wildcard(Path.join(path, "**/*.ex"))
    end
  end
end
