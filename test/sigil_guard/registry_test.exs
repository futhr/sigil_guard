defmodule SigilGuard.RegistryTest do
  @moduledoc """
  Tests for `SigilGuard.Registry`.

  Uses `Bypass` to simulate the SIGIL registry HTTP API, testing pattern
  bundle fetching, DID resolution, and error handling for network failures
  and malformed responses.
  """

  use ExUnit.Case, async: false

  alias SigilGuard.Registry

  setup do
    bypass = Bypass.open()
    start_supervised!({Finch, name: SigilGuard.Finch})
    %{bypass: bypass, url: "http://localhost:#{bypass.port}"}
  end

  describe "fetch_bundle/1" do
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
      assert {:error, _reason} = Registry.fetch_bundle(url: "http://localhost:1", timeout: 500)
    end

    test "returns error for invalid JSON", %{bypass: bypass, url: url} do
      Bypass.expect_once(bypass, "GET", "/patterns/bundle", fn conn ->
        Plug.Conn.resp(conn, 200, "not json")
      end)

      assert {:error, _reason} = Registry.fetch_bundle(url: url)
    end
  end

  describe "resolve_did/2" do
    test "resolves a DID document", %{bypass: bypass, url: url} do
      did_doc = %{
        "id" => "did:sigil:alice",
        "publicKey" => [%{"type" => "Ed25519VerificationKey2020", "publicKeyBase64" => "abc"}]
      }

      Bypass.expect_once(bypass, "GET", "/identities/did%3Asigil%3Aalice", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(did_doc))
      end)

      assert {:ok, ^did_doc} = Registry.resolve_did("did:sigil:alice", url: url)
    end

    test "returns error for unknown DID", %{bypass: bypass, url: url} do
      Bypass.expect_once(bypass, "GET", "/identities/did%3Asigil%3Aunknown", fn conn ->
        Plug.Conn.resp(conn, 404, Jason.encode!(%{"error" => "not found"}))
      end)

      assert {:error, {:http_error, 404}} = Registry.resolve_did("did:sigil:unknown", url: url)
    end
  end

  describe "fetch_policies/1" do
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
  end
end
