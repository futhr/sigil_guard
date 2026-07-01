defmodule SigilGuard.RegistryTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Registry

  setup do
    bypass = Bypass.open()
    start_supervised!({Finch, name: SigilGuard.Finch})
    %{bypass: bypass, url: "http://localhost:#{bypass.port}"}
  end

  describe "fetch_bundle/1" do
    test "requires an explicit registry URL" do
      Application.delete_env(:sigil_guard, :registry_url)

      assert {:error, :missing_registry_url} = Registry.fetch_bundle()
    end

    test "returns parsed bundle on success", %{bypass: bypass, url: url} do
      bundle = %{
        "generated_at" => "2024-01-01T00:00:00Z",
        "count" => 1,
        "patterns" => [
          %{"name" => "test", "regex" => "\\d+", "category" => "test", "severity" => "low"}
        ]
      }

      Bypass.expect_once(bypass, "GET", "/patterns/bundle", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(bundle))
      end)

      assert {:ok, ^bundle} = Registry.fetch_bundle(url: url)
    end

    test "returns error for non-200 status", %{bypass: bypass, url: url} do
      Bypass.expect_once(bypass, "GET", "/patterns/bundle", fn conn ->
        Plug.Conn.resp(conn, 404, "not found")
      end)

      assert {:error, {:http_error, 404}} = Registry.fetch_bundle(url: url)
    end

    test "returns error for server error", %{bypass: bypass, url: url} do
      Bypass.expect_once(bypass, "GET", "/patterns/bundle", fn conn ->
        Plug.Conn.resp(conn, 500, "internal error")
      end)

      assert {:error, {:http_error, 500}} = Registry.fetch_bundle(url: url)
    end

    test "returns error when server is unreachable" do
      assert {:error, _} = Registry.fetch_bundle(url: "http://localhost:1", timeout: 500)
    end

    test "rejects malformed timeouts before requesting", %{url: url} do
      assert {:error, :invalid_timeout} = Registry.fetch_bundle(url: url, timeout: "bad")
      assert {:error, :invalid_timeout} = Registry.fetch_bundle(url: url, timeout: -1)
    end

    test "returns error for invalid JSON", %{bypass: bypass, url: url} do
      Bypass.expect_once(bypass, "GET", "/patterns/bundle", fn conn ->
        Plug.Conn.resp(conn, 200, "not json")
      end)

      assert {:error, _} = Registry.fetch_bundle(url: url)
    end

    test "returns error for non-object JSON bodies", %{bypass: bypass, url: url} do
      for body <- [Jason.encode!([1, 2, 3]), Jason.encode!("scalar"), "42"] do
        Bypass.expect_once(bypass, "GET", "/patterns/bundle", fn conn ->
          Plug.Conn.resp(conn, 200, body)
        end)

        assert {:error, :invalid_body} = Registry.fetch_bundle(url: url)
      end
    end
  end

  describe "resolve_did/2" do
    test "requires an explicit registry URL" do
      Application.delete_env(:sigil_guard, :registry_url)

      assert {:error, :missing_registry_url} = Registry.resolve_did("did:sigil:alice")
    end

    test "resolves via /resolve by default", %{bypass: bypass, url: url} do
      did_doc = %{
        "did" => "did:sigil:alice",
        "status" => "active",
        "public_key" => public_key_b64u()
      }

      Bypass.expect_once(bypass, "GET", "/resolve/did%3Asigil%3Aalice", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(did_doc))
      end)

      assert {:ok, ^did_doc} = Registry.resolve_did("did:sigil:alice", url: url)
    end

    test "legacy profile resolves a DID document via /identities", %{bypass: bypass, url: url} do
      did_doc = %{
        "id" => "did:sigil:alice",
        "publicKey" => [
          %{"type" => "Ed25519VerificationKey2020", "publicKeyBase64" => public_key_b64()}
        ]
      }

      Bypass.expect_once(bypass, "GET", "/identities/did%3Asigil%3Aalice", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(did_doc))
      end)

      assert {:ok, ^did_doc} =
               Registry.resolve_did("did:sigil:alice", url: url, profile: :legacy_sigil_guard)
    end

    test "auto profile falls back from /resolve to /identities", %{bypass: bypass, url: url} do
      did_doc = %{
        "id" => "did:sigil:alice",
        "publicKey" => [%{"publicKeyBase64" => public_key_b64()}]
      }

      Bypass.expect_once(bypass, "GET", "/resolve/did%3Asigil%3Aalice", fn conn ->
        Plug.Conn.resp(conn, 404, Jason.encode!(%{"error" => "not found"}))
      end)

      Bypass.expect_once(bypass, "GET", "/identities/did%3Asigil%3Aalice", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(did_doc))
      end)

      assert {:ok, ^did_doc} = Registry.resolve_did("did:sigil:alice", url: url)
    end

    test "returns error for unknown DID", %{bypass: bypass, url: url} do
      Bypass.expect_once(bypass, "GET", "/resolve/did%3Asigil%3Aunknown", fn conn ->
        Plug.Conn.resp(conn, 404, Jason.encode!(%{"error" => "not found"}))
      end)

      Bypass.expect_once(bypass, "GET", "/identities/did%3Asigil%3Aunknown", fn conn ->
        Plug.Conn.resp(conn, 404, Jason.encode!(%{"error" => "not found"}))
      end)

      assert {:error, {:http_error, 404}} = Registry.resolve_did("did:sigil:unknown", url: url)
    end

    test "rejects malformed timeouts before DID resolution requests", %{url: url} do
      assert {:error, :invalid_timeout} =
               Registry.resolve_did("did:sigil:alice", url: url, timeout: false)

      assert {:error, :invalid_timeout} =
               Registry.resolve_did("did:sigil:alice", url: url, timeout: -1)
    end
  end

  describe "resolve_key/2" do
    test "normalizes flat public_key responses", %{bypass: bypass, url: url} do
      Bypass.expect_once(bypass, "GET", "/resolve/did%3Asigil%3Aalice", fn conn ->
        Plug.Conn.resp(
          conn,
          200,
          Jason.encode!(%{
            "did" => "did:sigil:alice",
            "status" => "active",
            "public_key" => public_key_b64u()
          })
        )
      end)

      assert {:ok, resolved} = Registry.resolve_key("did:sigil:alice", url: url)
      assert resolved.did == "did:sigil:alice"
      assert resolved.status == "active"
      assert resolved.raw_public_key == public_key_raw()
      assert resolved.public_key_b64u == public_key_b64u()
      assert resolved.source_format == :flat_public_key
    end

    test "normalizes JWK-like public_key responses", %{bypass: bypass, url: url} do
      Bypass.expect_once(bypass, "GET", "/resolve/did%3Asigil%3Aalice", fn conn ->
        Plug.Conn.resp(
          conn,
          200,
          Jason.encode!(%{
            "did" => "did:sigil:alice",
            "public_key" => %{"kty" => "OKP", "crv" => "Ed25519", "x" => public_key_b64u()}
          })
        )
      end)

      assert {:ok, resolved} = Registry.resolve_key("did:sigil:alice", url: url)
      assert resolved.raw_public_key == public_key_raw()
      assert resolved.source_format == :jwk_okp_x
    end

    test "normalizes legacy DID-doc publicKey arrays", %{bypass: bypass, url: url} do
      Bypass.expect_once(bypass, "GET", "/identities/did%3Asigil%3Aalice", fn conn ->
        Plug.Conn.resp(
          conn,
          200,
          Jason.encode!(%{
            "id" => "did:sigil:alice",
            "publicKey" => [%{"publicKeyBase64" => public_key_b64()}]
          })
        )
      end)

      assert {:ok, resolved} =
               Registry.resolve_key("did:sigil:alice",
                 url: url,
                 profile: :legacy_sigil_guard
               )

      assert resolved.raw_public_key == public_key_raw()
      assert resolved.public_key_b64u == public_key_b64u()
      assert resolved.source_format == :did_doc_publicKeyBase64
    end

    test "normalizes legacy DID-doc base64url publicKey arrays", %{bypass: bypass, url: url} do
      Bypass.expect_once(bypass, "GET", "/identities/did%3Asigil%3Aalice", fn conn ->
        Plug.Conn.resp(
          conn,
          200,
          Jason.encode!(%{
            "id" => "did:sigil:alice",
            "publicKey" => [%{"publicKeyBase64Url" => public_key_b64u()}]
          })
        )
      end)

      assert {:ok, resolved} =
               Registry.resolve_key("did:sigil:alice",
                 url: url,
                 profile: :legacy_sigil_guard
               )

      assert resolved.raw_public_key == public_key_raw()
      assert resolved.source_format == :did_doc_publicKeyBase64Url
    end

    test "rejects malformed key material", %{bypass: bypass, url: url} do
      Bypass.expect_once(bypass, "GET", "/resolve/did%3Asigil%3Aalice", fn conn ->
        Plug.Conn.resp(
          conn,
          200,
          Jason.encode!(%{"did" => "did:sigil:alice", "public_key" => "not-valid!"})
        )
      end)

      assert {:error, :invalid_base64} = Registry.resolve_key("did:sigil:alice", url: url)
    end

    test "does not let legacy publicKey mask malformed flat public_key", %{
      bypass: bypass,
      url: url
    } do
      Bypass.expect_once(bypass, "GET", "/resolve/did%3Asigil%3Aalice", fn conn ->
        Plug.Conn.resp(
          conn,
          200,
          Jason.encode!(%{
            "did" => "did:sigil:alice",
            "public_key" => false,
            "publicKey" => [%{"publicKeyBase64" => public_key_b64()}]
          })
        )
      end)

      assert {:error, :invalid_public_key} = Registry.resolve_key("did:sigil:alice", url: url)
    end

    test "does not let legacy publicKey mask malformed JWK public_key", %{
      bypass: bypass,
      url: url
    } do
      Bypass.expect_once(bypass, "GET", "/resolve/did%3Asigil%3Aalice", fn conn ->
        Plug.Conn.resp(
          conn,
          200,
          Jason.encode!(%{
            "did" => "did:sigil:alice",
            "public_key" => %{"kty" => "OKP", "crv" => "Ed25519", "x" => false},
            "publicKey" => [%{"publicKeyBase64" => public_key_b64()}]
          })
        )
      end)

      assert {:error, :invalid_public_key} = Registry.resolve_key("did:sigil:alice", url: url)
    end

    test "rejects wrong-length key material", %{bypass: bypass, url: url} do
      Bypass.expect_once(bypass, "GET", "/resolve/did%3Asigil%3Aalice", fn conn ->
        Plug.Conn.resp(
          conn,
          200,
          Jason.encode!(%{"did" => "did:sigil:alice", "public_key" => Base.encode64("short")})
        )
      end)

      assert {:error, :invalid_key} = Registry.resolve_key("did:sigil:alice", url: url)
    end

    test "rejects responses without usable public key material", %{bypass: bypass, url: url} do
      Bypass.expect_once(bypass, "GET", "/resolve/did%3Asigil%3Aalice", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"did" => "did:sigil:alice"}))
      end)

      assert {:error, :missing_public_key} = Registry.resolve_key("did:sigil:alice", url: url)
    end

    test "rejects DID-doc arrays without supported key entries", %{bypass: bypass, url: url} do
      Bypass.expect_once(bypass, "GET", "/identities/did%3Asigil%3Aalice", fn conn ->
        Plug.Conn.resp(
          conn,
          200,
          Jason.encode!(%{
            "id" => "did:sigil:alice",
            "publicKey" => [%{"type" => "Unsupported"}]
          })
        )
      end)

      assert {:error, :missing_public_key} =
               Registry.resolve_key("did:sigil:alice",
                 url: url,
                 profile: :legacy_sigil_guard
               )
    end

    test "does not let malformed DID-doc key entries fall through to later keys", %{
      bypass: bypass,
      url: url
    } do
      Bypass.expect_once(bypass, "GET", "/identities/did%3Asigil%3Aalice", fn conn ->
        Plug.Conn.resp(
          conn,
          200,
          Jason.encode!(%{
            "id" => "did:sigil:alice",
            "publicKey" => [
              %{"publicKeyBase64" => false},
              %{"publicKeyBase64" => public_key_b64()}
            ]
          })
        )
      end)

      assert {:error, :invalid_public_key} =
               Registry.resolve_key("did:sigil:alice",
                 url: url,
                 profile: :legacy_sigil_guard
               )
    end

    test "rejects key responses without a DID", %{bypass: bypass, url: url} do
      Bypass.expect_once(bypass, "GET", "/resolve/did%3Asigil%3Aalice", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"public_key" => public_key_b64u()}))
      end)

      assert {:error, :missing_did} = Registry.resolve_key("did:sigil:alice", url: url)
    end

    test "rejects malformed resolved identity statuses", %{bypass: bypass, url: url} do
      Bypass.expect_once(bypass, "GET", "/resolve/did%3Asigil%3Aalice", fn conn ->
        Plug.Conn.resp(
          conn,
          200,
          Jason.encode!(%{
            "did" => "did:sigil:alice",
            "status" => false,
            "public_key" => public_key_b64u()
          })
        )
      end)

      assert {:error, :invalid_status} = Registry.resolve_key("did:sigil:alice", url: url)

      Bypass.expect_once(bypass, "GET", "/identities/did%3Asigil%3Aalice", fn conn ->
        Plug.Conn.resp(
          conn,
          200,
          Jason.encode!(%{
            "id" => "did:sigil:alice",
            "status" => false,
            "publicKey" => [%{"publicKeyBase64" => public_key_b64()}]
          })
        )
      end)

      assert {:error, :invalid_status} =
               Registry.resolve_key("did:sigil:alice",
                 url: url,
                 profile: :legacy_sigil_guard
               )
    end

    test "does not let fallback IDs mask malformed primary DIDs", %{bypass: bypass, url: url} do
      Bypass.expect_once(bypass, "GET", "/resolve/did%3Asigil%3Aalice", fn conn ->
        Plug.Conn.resp(
          conn,
          200,
          Jason.encode!(%{
            "did" => false,
            "id" => "did:sigil:alice",
            "public_key" => public_key_b64u()
          })
        )
      end)

      assert {:error, :missing_did} = Registry.resolve_key("did:sigil:alice", url: url)

      Bypass.expect_once(bypass, "GET", "/identities/did%3Asigil%3Aalice", fn conn ->
        Plug.Conn.resp(
          conn,
          200,
          Jason.encode!(%{
            "id" => false,
            "did" => "did:sigil:alice",
            "publicKey" => [%{"publicKeyBase64" => public_key_b64()}]
          })
        )
      end)

      assert {:error, :missing_did} =
               Registry.resolve_key("did:sigil:alice",
                 url: url,
                 profile: :legacy_sigil_guard
               )
    end
  end

  describe "fetch_policies/1" do
    test "requires an explicit registry URL" do
      Application.delete_env(:sigil_guard, :registry_url)

      assert {:error, :missing_registry_url} = Registry.fetch_policies()
    end

    test "returns policy definitions", %{bypass: bypass, url: url} do
      policies = %{
        "policies" => [
          %{"action" => "delete_*", "risk" => "critical", "trust" => "sovereign"}
        ]
      }

      Bypass.expect_once(bypass, "GET", "/policies", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(policies))
      end)

      assert {:ok, ^policies} = Registry.fetch_policies(url: url)
    end

    test "rejects malformed timeouts before policy requests", %{url: url} do
      assert {:error, :invalid_timeout} = Registry.fetch_policies(url: url, timeout: :bad)
      assert {:error, :invalid_timeout} = Registry.fetch_policies(url: url, timeout: -1)
    end
  end

  defp public_key_raw, do: :binary.copy(<<1>>, 32)
  defp public_key_b64u, do: Base.url_encode64(public_key_raw(), padding: false)
  defp public_key_b64, do: Base.encode64(public_key_raw())
end
