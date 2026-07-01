defmodule SigilGuard.Audit.Anchor.Store.HTTPTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Audit
  alias SigilGuard.Audit.Anchor
  alias SigilGuard.Audit.Anchor.Store
  alias SigilGuard.Audit.Anchor.Store.HTTP
  alias SigilGuard.Audit.Checkpoint
  alias SigilGuard.TestSigner

  @secret_key :crypto.hash(:sha256, "audit http anchor store test key")
  @generated_at "2026-01-01T00:00:00.000Z"
  @anchored_at "2026-01-01T00:00:05.000Z"
  @issuer "did:web:http-anchor-store.example"

  setup do
    bypass = Bypass.open()
    start_supervised!({Finch, name: SigilGuard.Finch})
    %{bypass: bypass, url: "http://localhost:#{bypass.port}"}
  end

  describe "put/3" do
    test "posts compact anchors and normalizes remote receipts", %{bypass: bypass, url: url} do
      {_, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)

      Bypass.expect_once(bypass, "POST", "/audit/anchors", fn conn ->
        assert ["application/json"] = Plug.Conn.get_req_header(conn, "accept")
        assert ["application/json"] = Plug.Conn.get_req_header(conn, "content-type")
        assert ["Bearer anchor-test"] = Plug.Conn.get_req_header(conn, "authorization")

        {:ok, body, conn} = Plug.Conn.read_body(conn)
        decoded = Jason.decode!(body)

        assert decoded["kind"] == "sigil_guard.audit.anchor.put"
        assert decoded["version"] == 1
        assert decoded["anchor_digest"] == digest
        assert decoded["record"] == anchor
        assert decoded["metadata"] == %{"env" => "test"}

        receipt = %{
          "kind" => "sigil_guard.audit.anchor.receipt",
          "version" => 1,
          "storage" => "worm_gateway",
          "uri" => "#{url}/audit/anchors/#{digest}##{digest}",
          "anchor_digest" => digest,
          "stored_at" => "2026-01-01T00:00:06.000Z",
          "worm" => true,
          "metadata" => %{"region" => "eu"}
        }

        Plug.Conn.resp(conn, 201, Jason.encode!(%{"receipt" => receipt}))
      end)

      assert {:ok, receipt} =
               Store.put(HTTP, anchor,
                 url: url,
                 metadata: %{"env" => "test"},
                 headers: [{"authorization", "Bearer anchor-test"}]
               )

      assert receipt["kind"] == "sigil_guard.audit.anchor.receipt"
      assert receipt["storage"] == "worm_gateway"
      assert receipt["uri"] == "#{url}/audit/anchors/#{digest}##{digest}"
      assert receipt["anchor_digest"] == digest
      assert receipt["stored_at"] == "2026-01-01T00:00:06.000Z"
      assert receipt["worm"]
      assert receipt["metadata"] == %{"region" => "eu"}
    end

    test "accepts empty successful responses and uses Location receipts", %{
      bypass: bypass,
      url: url
    } do
      {_, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)
      location = "#{url}/audit/anchors/#{digest}##{digest}"

      Bypass.expect_once(bypass, "POST", "/audit/anchors", fn conn ->
        conn
        |> Plug.Conn.put_resp_header("location", location)
        |> Plug.Conn.resp(202, "")
      end)

      assert {:ok, receipt} = Store.put(HTTP, anchor, url: url)

      assert receipt["storage"] == "http"
      assert receipt["uri"] == location
      assert receipt["anchor_digest"] == digest
      refute receipt["worm"]
      assert receipt["metadata"] == %{}
    end

    test "requires explicit WORM receipts when requested", %{bypass: bypass, url: url} do
      {_, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)

      Bypass.expect_once(bypass, "POST", "/audit/anchors", fn conn ->
        Plug.Conn.resp(
          conn,
          201,
          Jason.encode!(%{"anchor_digest" => digest, "worm" => true})
        )
      end)

      assert {:ok, receipt} = Store.put(HTTP, anchor, url: url, require_worm: true)
      assert receipt["worm"]

      Bypass.expect_once(bypass, "POST", "/audit/anchors", fn conn ->
        Plug.Conn.resp(
          conn,
          201,
          Jason.encode!(%{"anchor_digest" => digest, "worm" => false})
        )
      end)

      assert {:error, :worm_required} =
               Store.put(HTTP, anchor, url: url, require_worm: true)

      Bypass.expect_once(bypass, "POST", "/audit/anchors", fn conn ->
        Plug.Conn.resp(
          conn,
          201,
          Jason.encode!(%{"anchor_digest" => digest, "worm" => "true"})
        )
      end)

      assert {:error, :worm_required} = HTTP.put(anchor, url: url, require_worm: true)
    end

    test "supports explicit put URLs and map headers", %{bypass: bypass, url: url} do
      {_, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)

      Bypass.expect_once(bypass, "POST", "/custom/anchors", fn conn ->
        assert ["Bearer map-token"] = Plug.Conn.get_req_header(conn, "authorization")
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"anchor_digest" => digest}))
      end)

      assert {:ok, receipt} =
               Store.put(HTTP, anchor,
                 put_url: "#{url}/custom/anchors",
                 headers: %{authorization: "Bearer map-token"}
               )

      assert receipt["anchor_digest"] == digest
      assert receipt["uri"] == "#{url}/custom/anchors##{digest}"
    end

    test "supports base URLs with custom put paths", %{bypass: bypass, url: url} do
      {_, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)

      Bypass.expect_once(bypass, "POST", "/v1/anchors", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"anchor_digest" => digest}))
      end)

      assert {:ok, receipt} =
               Store.put(HTTP, anchor,
                 base_url: url,
                 put_path: "/v1/anchors"
               )

      assert receipt["anchor_digest"] == digest
    end
  end

  describe "fetch/3 and verify/4" do
    test "fetches anchors by receipt URI and verifies them", %{bypass: bypass, url: url} do
      {checkpoint, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)

      Bypass.expect(bypass, "GET", "/audit/anchors/#{digest}", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"record" => anchor}))
      end)

      receipt = %{
        "kind" => "sigil_guard.audit.anchor.receipt",
        "storage" => "http",
        "uri" => "#{url}/audit/anchors/#{digest}##{digest}",
        "anchor_digest" => digest
      }

      assert {:ok, ^anchor} = Store.fetch(HTTP, receipt)

      assert {:ok, verified} = Store.verify(HTTP, receipt, checkpoint)
      assert verified.digest == digest
      assert verified.record == anchor
    end

    test "fetches anchors when only the receipt URI fragment carries the digest", %{
      bypass: bypass,
      url: url
    } do
      {_, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)

      Bypass.expect_once(bypass, "GET", "/audit/anchors/#{digest}", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(anchor))
      end)

      assert {:ok, ^anchor} =
               Store.fetch(HTTP, %{"uri" => "#{url}/audit/anchors/#{digest}##{digest}"})
    end

    test "fetches anchors by digest through a custom endpoint", %{bypass: bypass, url: url} do
      {_, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)

      Bypass.expect_once(bypass, "GET", "/v1/anchors/#{digest}", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"anchor" => anchor}))
      end)

      assert {:ok, ^anchor} =
               Store.fetch(HTTP, digest,
                 url: url,
                 fetch_path: "/v1/anchors/:digest"
               )
    end

    test "fetches anchors through explicit fetch URLs and base URLs", %{bypass: bypass, url: url} do
      {_, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)

      Bypass.expect_once(bypass, "GET", "/explicit/#{digest}", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(anchor))
      end)

      assert {:ok, ^anchor} =
               Store.fetch(HTTP, digest, fetch_url: "#{url}/explicit/:digest")

      Bypass.expect_once(bypass, "GET", "/base/#{digest}", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"record" => anchor}))
      end)

      assert {:ok, ^anchor} =
               Store.fetch(HTTP, digest,
                 base_url: url,
                 fetch_path: "/base/:digest"
               )
    end
  end

  describe "error handling" do
    test "rejects invalid inputs before requests", %{url: url} do
      {_, anchor} = anchor_fixture()

      assert {:error, :missing_url} = Store.put(HTTP, anchor)

      assert {:error, :invalid_anchor} =
               Store.put(HTTP, %{"kind" => "other"}, url: url)

      assert {:error, :invalid_metadata} =
               Store.put(HTTP, anchor, url: url, metadata: "bad")

      assert {:error, :invalid_headers} =
               Store.put(HTTP, anchor, url: url, headers: [{"x-bad", %{nested: true}}])

      assert {:error, :invalid_headers} = Store.put(HTTP, anchor, url: url, headers: "bad")

      assert {:error, :missing_digest} = Store.fetch(HTTP, %{}, url: url)
      assert {:error, :missing_url} = Store.fetch(HTTP, Anchor.digest(anchor))

      assert {:error, :missing_url} =
               Store.fetch(HTTP, %{
                 uri: "s3://anchors/object",
                 anchor_digest: Anchor.digest(anchor)
               })

      assert {:error, :invalid_anchor} = HTTP.put("bad", [])
      assert {:error, :missing_url} = HTTP.fetch(Anchor.digest(anchor), :bad)
      assert {:error, :missing_digest} = HTTP.fetch(:bad, [])
    end

    test "returns HTTP and body errors", %{bypass: bypass, url: url} do
      {_, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)

      Bypass.expect_once(bypass, "POST", "/audit/anchors", fn conn ->
        Plug.Conn.resp(conn, 500, "server error")
      end)

      assert {:error, {:http_error, 500}} = Store.put(HTTP, anchor, url: url)

      Bypass.expect_once(bypass, "GET", "/audit/anchors/#{digest}", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(["not", "object"]))
      end)

      assert {:error, :invalid_body} = Store.fetch(HTTP, digest, url: url)

      Bypass.expect_once(bypass, "GET", "/audit/anchors/#{digest}", fn conn ->
        Plug.Conn.resp(conn, 200, "")
      end)

      assert {:error, :invalid_body} = Store.fetch(HTTP, digest, url: url)

      Bypass.expect_once(bypass, "GET", "/audit/anchors/#{digest}", fn conn ->
        Plug.Conn.resp(conn, 200, "not json")
      end)

      assert {:error, :invalid_body} = Store.fetch(HTTP, digest, url: url)
    end

    test "returns transport errors", %{bypass: bypass} do
      {_, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)

      Bypass.down(bypass)

      assert {:error, _} =
               Store.fetch(HTTP, digest,
                 url: "http://localhost:#{bypass.port}",
                 timeout: 50
               )
    end

    test "detects remote receipt and fetched record digest mismatches", %{
      bypass: bypass,
      url: url
    } do
      {_, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)
      wrong_digest = String.duplicate("0", 64)

      Bypass.expect_once(bypass, "POST", "/audit/anchors", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"anchor_digest" => wrong_digest}))
      end)

      assert {:error, :digest_mismatch} = Store.put(HTTP, anchor, url: url)

      Bypass.expect_once(bypass, "GET", "/audit/anchors/#{digest}", fn conn ->
        tampered = Map.put(anchor, "storage", "tampered")
        Plug.Conn.resp(conn, 200, Jason.encode!(tampered))
      end)

      assert {:error, :digest_mismatch} = Store.fetch(HTTP, digest, url: url)
    end

    test "rejects responses without anchor records", %{bypass: bypass, url: url} do
      {_, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)

      Bypass.expect_once(bypass, "GET", "/audit/anchors/#{digest}", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"record" => %{"kind" => "other"}}))
      end)

      assert {:error, :invalid_anchor} = Store.fetch(HTTP, digest, url: url)
    end
  end

  defp anchor_fixture do
    events =
      1..3
      |> Enum.map(&Audit.new_event("test", "alice", "http-anchor-store-#{&1}", "ok"))
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
end
