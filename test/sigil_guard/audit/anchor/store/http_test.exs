defmodule SigilGuard.Audit.Anchor.Store.HTTPTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Audit
  alias SigilGuard.Audit.Anchor
  alias SigilGuard.Audit.Anchor.Receipt
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
    Application.put_env(:sigil_guard, :http_client, SigilGuard.TestHTTPClient)
    on_exit(fn -> Application.delete_env(:sigil_guard, :http_client) end)
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

    test "rejects malformed remote receipt fields instead of defaulting them", %{
      bypass: bypass,
      url: url
    } do
      {_, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)

      invalid_receipts = [
        %{"receipt" => false},
        %{"anchor_digest" => false},
        %{"anchor_digest" => digest, "kind" => false},
        %{"anchor_digest" => digest, "kind" => "wrong"},
        %{"anchor_digest" => digest, "version" => false},
        %{"anchor_digest" => digest, "storage" => false},
        %{"anchor_digest" => digest, "stored_at" => false},
        %{"anchor_digest" => digest, "worm" => "true"},
        %{"anchor_digest" => digest, "metadata" => false}
      ]

      Enum.each(invalid_receipts, fn receipt ->
        Bypass.expect_once(bypass, "POST", "/audit/anchors", fn conn ->
          Plug.Conn.resp(conn, 201, Jason.encode!(receipt))
        end)

        assert {:error, :invalid_receipt} =
                 Store.put(HTTP, anchor,
                   url: url,
                   metadata: %{"request" => "metadata"}
                 )
      end)
    end

    test "does not let response Location mask malformed receipt URIs", %{
      bypass: bypass,
      url: url
    } do
      {_, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)
      location = "#{url}/audit/anchors/#{digest}##{digest}"

      Bypass.expect_once(bypass, "POST", "/audit/anchors", fn conn ->
        conn
        |> Plug.Conn.put_resp_header("location", location)
        |> Plug.Conn.resp(201, Jason.encode!(%{"anchor_digest" => digest, "uri" => false}))
      end)

      assert {:error, :invalid_receipt} = Store.put(HTTP, anchor, url: url)
    end

    test "rejects remote receipts whose URI fragment conflicts with the anchor digest", %{
      bypass: bypass,
      url: url
    } do
      {_, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)
      wrong_digest = String.duplicate("0", 64)

      Bypass.expect_once(bypass, "POST", "/audit/anchors", fn conn ->
        Plug.Conn.resp(
          conn,
          201,
          Jason.encode!(%{
            "anchor_digest" => digest,
            "uri" => "#{url}/audit/anchors/#{digest}##{wrong_digest}"
          })
        )
      end)

      assert {:error, :digest_mismatch} = Store.put(HTTP, anchor, url: url)
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

      assert {:error, :invalid_receipt} = HTTP.put(anchor, url: url, require_worm: true)
    end

    test "requires valid signed receipts when requested", %{bypass: bypass, url: url} do
      {_, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)

      receipt =
        url
        |> receipt_fixture(digest)
        |> sign_receipt()

      expect_receipt(bypass, receipt)

      assert {:ok, verified_receipt} =
               Store.put(HTTP, anchor,
                 url: url,
                 require_worm: true,
                 require_receipt_signature: true,
                 receipt_public_keys: %{@issuer => TestSigner.public_key_b64u()}
               )

      assert verified_receipt["anchor_digest"] == digest
      assert verified_receipt["worm"]
      assert get_in(verified_receipt, ["signature", "issuer"]) == @issuer
      assert get_in(verified_receipt, ["signature", "algorithm"]) == "Ed25519"
    end

    test "rejects unsigned and untrusted receipts when signatures are required", %{
      bypass: bypass,
      url: url
    } do
      {_, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)
      receipt = receipt_fixture(url, digest)

      expect_receipt(bypass, receipt)

      assert {:error, :unsigned_receipt} =
               Store.put(HTTP, anchor, url: url, require_receipt_signature: true)

      expect_receipt(bypass, Map.put(receipt, "signature", "bad"))

      assert {:error, :invalid_signature_metadata} =
               Store.put(HTTP, anchor, url: url, require_receipt_signature: true)

      expect_receipt(bypass, sign_receipt(receipt))

      assert {:error, :unknown_issuer} =
               Store.put(HTTP, anchor, url: url, require_receipt_signature: true)

      expect_receipt(bypass, sign_receipt(receipt))

      assert {:error, :invalid_public_keys} =
               Store.put(HTTP, anchor,
                 url: url,
                 require_receipt_signature: true,
                 receipt_public_keys: "bad"
               )
    end

    test "rejects signed receipts with invalid provenance", %{bypass: bypass, url: url} do
      {_, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)
      receipt = receipt_fixture(url, digest)

      opts = [
        url: url,
        require_receipt_signature: true,
        receipt_public_key_b64u: TestSigner.public_key_b64u()
      ]

      expect_receipt(bypass, sign_receipt(receipt, digest: String.duplicate("0", 64)))

      assert {:error, :digest_mismatch} = Store.put(HTTP, anchor, opts)

      bad_signature = Base.url_encode64(:binary.copy(<<0>>, 64), padding: false)
      expect_receipt(bypass, sign_receipt(receipt, signature: bad_signature))

      assert {:error, :invalid_signature} = Store.put(HTTP, anchor, opts)

      expect_receipt(bypass, sign_receipt(receipt, algorithm: "Ed448"))

      assert {:error, :unsupported_algorithm} = Store.put(HTTP, anchor, opts)

      bad_public_key = Base.url_encode64(<<1, 2, 3>>, padding: false)
      expect_receipt(bypass, sign_receipt(receipt))

      assert {:error, :invalid_key} =
               Store.put(HTTP, anchor,
                 url: url,
                 require_receipt_signature: true,
                 receipt_public_key_b64u: bad_public_key
               )

      invalid_public_key = "not!base64"
      expect_receipt(bypass, sign_receipt(receipt))

      assert {:error, :invalid_base64} =
               Store.put(HTTP, anchor,
                 url: url,
                 require_receipt_signature: true,
                 receipt_public_key_b64u: invalid_public_key
               )

      standard_base64_wrong_key = Base.encode64(:binary.copy(<<255>>, 32))
      expect_receipt(bypass, sign_receipt(receipt))

      assert {:error, :invalid_signature} =
               Store.put(HTTP, anchor,
                 url: url,
                 require_receipt_signature: true,
                 receipt_public_key_b64u: standard_base64_wrong_key
               )

      short_signature = Base.url_encode64("short", padding: false)
      expect_receipt(bypass, sign_receipt(receipt, signature: short_signature))

      assert {:error, :invalid_signature} = Store.put(HTTP, anchor, opts)

      invalid_signature = "not!base64"
      expect_receipt(bypass, sign_receipt(receipt, signature: invalid_signature))

      assert {:error, :invalid_base64} = Store.put(HTTP, anchor, opts)
    end

    test "rejects signed receipts with incomplete provenance", %{bypass: bypass, url: url} do
      {_, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)
      receipt = receipt_fixture(url, digest)
      opts = [url: url, require_receipt_signature: true]

      missing_issuer = update_in(sign_receipt(receipt), ["signature"], &Map.delete(&1, "issuer"))
      expect_receipt(bypass, missing_issuer)

      assert {:error, :missing_issuer} = Store.put(HTTP, anchor, opts)

      missing_algorithm =
        update_in(sign_receipt(receipt), ["signature"], &Map.delete(&1, "algorithm"))

      expect_receipt(bypass, missing_algorithm)

      assert {:error, :missing_algorithm} = Store.put(HTTP, anchor, opts)

      missing_signature =
        update_in(sign_receipt(receipt), ["signature"], &Map.delete(&1, "signature"))

      expect_receipt(bypass, missing_signature)

      assert {:error, :missing_signature} = Store.put(HTTP, anchor, opts)
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

      opts = [allow_private_receipt_url: true]

      assert {:ok, ^anchor} = Store.fetch(HTTP, receipt, opts)

      assert {:ok, verified} = Store.verify(HTTP, receipt, checkpoint, opts)
      assert verified.digest == digest
      assert verified.record == anchor
    end

    test "requires signed receipts during fetch and verify when requested", %{
      bypass: bypass,
      url: url
    } do
      {checkpoint, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)

      signed_receipt =
        url
        |> receipt_fixture(digest)
        |> sign_receipt()

      Bypass.expect(bypass, "GET", "/audit/anchors/#{digest}", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"record" => anchor}))
      end)

      opts = [
        allow_private_receipt_url: true,
        require_receipt_signature: true,
        receipt_public_keys: %{@issuer => TestSigner.public_key_b64u()}
      ]

      assert {:ok, ^anchor} = Store.fetch(HTTP, signed_receipt, opts)

      assert {:ok, verified} =
               Store.verify(HTTP, signed_receipt, checkpoint, opts)

      assert verified.digest == digest

      unsigned_receipt = Map.delete(signed_receipt, "signature")

      assert {:error, :unsigned_receipt} =
               Store.fetch(HTTP, unsigned_receipt, opts)

      tampered_receipt =
        put_in(signed_receipt, ["uri"], "#{url}/audit/anchors/tampered##{digest}")

      assert {:error, :digest_mismatch} =
               Store.fetch(HTTP, tampered_receipt, opts)

      assert {:error, :missing_receipt} =
               Store.fetch(HTTP, digest, Keyword.put(opts, :url, url))
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
               Store.fetch(HTTP, %{"uri" => "#{url}/audit/anchors/#{digest}##{digest}"},
                 allow_private_receipt_url: true
               )
    end

    test "rejects receipts with malformed explicit digests before URI fallback", %{
      url: url
    } do
      {_, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)
      receipt = receipt_fixture(url, digest)

      assert {:error, :missing_digest} =
               Store.fetch(HTTP, Map.put(receipt, "anchor_digest", false))

      atom_receipt =
        receipt
        |> Map.delete("anchor_digest")
        |> Map.put(:anchor_digest, false)

      assert {:error, :missing_digest} = Store.fetch(HTTP, atom_receipt)
    end

    test "rejects receipts whose explicit digest conflicts with URI fragment", %{url: url} do
      {_, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)
      wrong_digest = String.duplicate("0", 64)

      receipt =
        url
        |> receipt_fixture(digest)
        |> Map.put("uri", "#{url}/audit/anchors/#{digest}##{wrong_digest}")

      assert {:error, :digest_mismatch} = Store.fetch(HTTP, receipt)
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

      assert {:error, :missing_anchored_at} =
               Store.put(HTTP, Map.delete(anchor, "anchored_at"), url: url)

      assert {:error, :invalid_metadata} =
               Store.put(HTTP, anchor, url: url, metadata: "bad")

      assert {:error, :invalid_metadata} =
               Store.put(HTTP, anchor, url: url, metadata: %{"pid" => self()})

      assert {:error, :invalid_metadata} =
               Store.put(HTTP, anchor, url: url, metadata: %{{:tuple, :key} => "bad"})

      assert {:error, :invalid_headers} =
               Store.put(HTTP, anchor, url: url, headers: [{"x-bad", %{nested: true}}])

      assert {:error, :invalid_headers} = Store.put(HTTP, anchor, url: url, headers: "bad")
      assert {:error, :invalid_timeout} = Store.put(HTTP, anchor, url: url, timeout: "bad")
      assert {:error, :invalid_timeout} = Store.put(HTTP, anchor, url: url, timeout: -1)

      assert {:error, :missing_digest} = Store.fetch(HTTP, %{}, url: url)
      assert {:error, :missing_url} = Store.fetch(HTTP, Anchor.digest(anchor))

      assert {:error, :invalid_timeout} =
               Store.fetch(HTTP, Anchor.digest(anchor), url: url, timeout: false)

      assert {:error, :invalid_timeout} =
               Store.fetch(HTTP, Anchor.digest(anchor), url: url, timeout: -1)

      assert {:error, :missing_url} =
               Store.fetch(HTTP, %{
                 uri: "s3://anchors/object",
                 anchor_digest: Anchor.digest(anchor)
               })

      assert {:error, :invalid_anchor} = HTTP.put("bad", [])
      assert {:error, :missing_url} = HTTP.fetch(Anchor.digest(anchor), :bad)
      assert {:error, :missing_digest} = HTTP.fetch(:bad, [])
    end

    test "rejects private receipt URLs by default" do
      {_, anchor} = anchor_fixture()
      digest = Anchor.digest(anchor)

      unsafe_uris = [
        "http://localhost/audit/anchors/#{digest}##{digest}",
        "http://anchor.localhost/audit/anchors/#{digest}##{digest}",
        "http://0.0.0.0/audit/anchors/#{digest}##{digest}",
        "http://127.0.0.1/audit/anchors/#{digest}##{digest}",
        "http://10.0.0.1/audit/anchors/#{digest}##{digest}",
        "http://100.64.0.1/audit/anchors/#{digest}##{digest}",
        "http://172.16.0.1/audit/anchors/#{digest}##{digest}",
        "http://192.168.0.1/audit/anchors/#{digest}##{digest}",
        "http://198.18.0.1/audit/anchors/#{digest}##{digest}",
        "http://169.254.169.254/latest/meta-data##{digest}",
        "http://[::]/audit/anchors/#{digest}##{digest}",
        "http://[::1]/audit/anchors/#{digest}##{digest}",
        "http://[fd00::1]/audit/anchors/#{digest}##{digest}",
        "http://[fe80::1]/audit/anchors/#{digest}##{digest}"
      ]

      Enum.each(unsafe_uris, fn uri ->
        assert {:error, :unsafe_receipt_url} =
                 Store.fetch(HTTP, %{
                   "uri" => uri,
                   "anchor_digest" => digest
                 })
      end)
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

  defp receipt_fixture(url, digest) do
    %{
      "kind" => "sigil_guard.audit.anchor.receipt",
      "version" => 1,
      "storage" => "worm_gateway",
      "uri" => "#{url}/audit/anchors/#{digest}##{digest}",
      "anchor_digest" => digest,
      "stored_at" => "2026-01-01T00:00:06.000Z",
      "worm" => true,
      "metadata" => %{"region" => "eu", "replicas" => ["a", "b"]}
    }
  end

  defp expect_receipt(bypass, receipt) do
    Bypass.expect_once(bypass, "POST", "/audit/anchors", fn conn ->
      Plug.Conn.resp(conn, 201, Jason.encode!(%{"receipt" => receipt}))
    end)
  end

  defp sign_receipt(receipt, opts \\ []) do
    signed = Receipt.sign(receipt, TestSigner, issuer: Keyword.get(opts, :issuer, @issuer))

    signature =
      signed
      |> Map.fetch!("signature")
      |> maybe_override_signature("algorithm", :algorithm, opts)
      |> maybe_override_signature("digest", :digest, opts)
      |> maybe_override_signature("signature", :signature, opts)

    signed
    |> Map.delete("signature")
    |> Map.put("signature", signature)
  end

  defp maybe_override_signature(signature, field, opt, opts) do
    if Keyword.has_key?(opts, opt) do
      Map.put(signature, field, Keyword.fetch!(opts, opt))
    else
      signature
    end
  end
end

defmodule SigilGuard.Audit.Anchor.Store.HTTPNoClientTest do
  use ExUnit.Case, async: false

  alias SigilGuard.Audit.Anchor.Store
  alias SigilGuard.Audit.Anchor.Store.HTTP

  test "fails closed with :http_client_not_configured when no client is configured" do
    # No per-call :http_client and no app-env client: the store must not silently
    # no-op, and it makes no direct network call of its own (D9).
    assert Application.get_env(:sigil_guard, :http_client) == nil

    assert {:error, :http_client_not_configured} =
             Store.fetch(HTTP, String.duplicate("a", 64),
               url: "http://localhost:1",
               timeout: 1
             )
  end
end
