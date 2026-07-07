defmodule SigilGuard.Audit.Anchor.Store.HTTPContractTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Audit
  alias SigilGuard.Audit.Anchor
  alias SigilGuard.Audit.Anchor.Receipt
  alias SigilGuard.Audit.Anchor.Store
  alias SigilGuard.Audit.Anchor.Store.HTTP
  alias SigilGuard.Audit.Checkpoint
  alias SigilGuard.TestSigner

  @secret_key :crypto.hash(:sha256, "audit http anchor contract test key")
  @generated_at "2026-01-01T00:00:00.000Z"
  @anchored_at "2026-01-01T00:00:05.000Z"
  @issuer "did:web:audit.example.internal"

  setup do
    bypass = Bypass.open()
    Application.put_env(:sigil_guard, :http_client, SigilGuard.TestHTTPClient)
    on_exit(fn -> Application.delete_env(:sigil_guard, :http_client) end)
    %{bypass: bypass, url: "http://localhost:#{bypass.port}"}
  end

  test "strict remote anchor service round-trips signed WORM receipts", %{
    bypass: bypass,
    url: url
  } do
    {checkpoint, anchor} = anchor_fixture()
    digest = Anchor.digest(anchor)
    public_keys = %{@issuer => TestSigner.public_key_b64u()}

    Bypass.expect_once(bypass, "POST", "/audit/anchors", fn conn ->
      assert ["application/json"] = Plug.Conn.get_req_header(conn, "accept")
      assert ["application/json"] = Plug.Conn.get_req_header(conn, "content-type")

      {:ok, body, conn} = Plug.Conn.read_body(conn)
      payload = Jason.decode!(body)

      assert payload["kind"] == "sigil_guard.audit.anchor.put"
      assert payload["version"] == 1
      assert payload["anchor_digest"] == digest
      assert payload["record"] == anchor
      assert payload["metadata"] == %{"tenant" => "prod"}

      receipt =
        url
        |> receipt_fixture(digest)
        |> Receipt.sign(TestSigner, issuer: @issuer)

      Plug.Conn.resp(conn, 201, Jason.encode!(%{"receipt" => receipt}))
    end)

    assert {:ok, receipt} =
             Store.put(HTTP, anchor,
               url: url,
               metadata: %{"tenant" => "prod"},
               require_worm: true,
               require_receipt_signature: true,
               receipt_public_keys: public_keys
             )

    assert receipt["worm"] == true
    assert receipt["anchor_digest"] == digest
    assert get_in(receipt, ["signature", "issuer"]) == @issuer
    assert :ok = Receipt.verify(receipt, public_keys: public_keys)

    Bypass.expect_once(bypass, "GET", "/audit/anchors/#{digest}", fn conn ->
      assert ["application/json"] = Plug.Conn.get_req_header(conn, "accept")

      Plug.Conn.resp(conn, 200, Jason.encode!(%{"record" => anchor}))
    end)

    assert {:ok, verified} =
             Store.verify(HTTP, receipt, checkpoint,
               allow_private_receipt_url: true,
               require_receipt_signature: true,
               receipt_public_keys: public_keys
             )

    assert verified.record == anchor
    assert verified.digest == digest
  end

  defp anchor_fixture do
    events =
      1..3
      |> Enum.map(&Audit.new_event("test", "alice", "http-anchor-contract-#{&1}", "ok"))
      |> Audit.build_chain(@secret_key)

    {:ok, checkpoint} =
      Checkpoint.create(events,
        chain_id: "chain-a",
        generated_at: @generated_at
      )

    signed_checkpoint =
      Checkpoint.sign(checkpoint, TestSigner, issuer: @issuer, issued_at: @generated_at)

    anchor =
      Anchor.create(signed_checkpoint,
        anchored_at: @anchored_at,
        storage: :http,
        uri: "https://anchors.example.test/audit/anchors/1"
      )

    {signed_checkpoint, anchor}
  end

  defp receipt_fixture(url, digest) do
    %{
      "kind" => "sigil_guard.audit.anchor.receipt",
      "version" => 1,
      "storage" => "worm_gateway",
      "uri" => "#{url}/audit/anchors/#{digest}##{digest}",
      "anchor_digest" => digest,
      "stored_at" => "2026-01-01T00:00:06.000Z",
      "worm" => true,
      "metadata" => %{"service" => "contract"}
    }
  end
end
