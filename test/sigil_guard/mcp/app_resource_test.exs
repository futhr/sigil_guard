defmodule SigilGuard.MCP.AppResourceTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.MCP.AppResource

  @html "<!doctype html><title>Verified app</title>"

  doctest AppResource

  test "verifies pinned UI bytes and least-privilege browser metadata" do
    resource = resource()

    assert {:ok, verified} =
             AppResource.verify(resource,
               expected_uri: "ui://repo/review",
               expected_sha256: digest(@html),
               allowed_connect_domains: ["https://api.example.test"],
               allowed_resource_domains: ["https://cdn.example.test"],
               allowed_permissions: [:clipboardWrite]
             )

    assert verified.uri == "ui://repo/review"
    assert verified.mime_type == "text/html;profile=mcp-app"
    assert verified.sha256 == digest(@html)
    assert verified.permissions == ["clipboardWrite"]
  end

  test "requires a digest unless review mode explicitly disables pinning" do
    assert AppResource.verify(resource()) == {:error, :missing_resource_digest}

    assert {:ok, _} =
             AppResource.verify(resource(),
               require_digest: false,
               allowed_connect_domains: ["https://api.example.test"],
               allowed_resource_domains: ["https://cdn.example.test"],
               allowed_permissions: ["clipboardWrite"]
             )
  end

  test "rejects byte drift, URI drift, MIME drift, and non-UI schemes" do
    opts = [
      expected_uri: "ui://repo/review",
      expected_sha256: digest(@html),
      allowed_connect_domains: ["https://api.example.test"],
      allowed_resource_domains: ["https://cdn.example.test"],
      allowed_permissions: [:clipboardWrite]
    ]

    assert AppResource.verify(Map.put(resource(), "text", @html <> "!"), opts) ==
             {:error, :resource_digest_mismatch}

    assert AppResource.verify(resource(), Keyword.put(opts, :expected_uri, "ui://other/app")) ==
             {:error, :invalid_app_resource}

    assert AppResource.verify(Map.put(resource(), "mimeType", "text/html"), opts) ==
             {:error, :invalid_app_resource}

    assert AppResource.verify(Map.put(resource(), "uri", "https://example.test/app"), opts) ==
             {:error, :invalid_app_resource}
  end

  test "rejects undeclared domains, permissions, malformed metadata, and options" do
    assert AppResource.verify(resource(),
             expected_sha256: digest(@html),
             allowed_permissions: [:clipboardWrite]
           ) == {:error, :domain_not_allowed}

    assert AppResource.verify(resource(),
             expected_sha256: digest(@html),
             allowed_connect_domains: ["https://api.example.test"],
             allowed_resource_domains: ["https://cdn.example.test"]
           ) == {:error, :permission_not_allowed}

    malformed = put_in(resource(), ["_meta", "ui", "permissions", "camera"], true)

    assert AppResource.verify(malformed, expected_sha256: digest(@html)) ==
             {:error, :invalid_app_resource}

    assert AppResource.verify(resource(), expected_sha256: "bad") ==
             {:error, :invalid_options}

    assert AppResource.verify(resource(), :not_options) == {:error, :invalid_options}
  end

  test "supports pinned blob bytes and host-defined dedicated app domains" do
    resource =
      resource()
      |> Map.delete("text")
      |> Map.put("blob", Base.encode64(@html))
      |> put_in(["_meta", "ui", "domain"], "review.example.test")
      |> put_in(["_meta", "ui", "prefersBorder"], true)

    opts = [
      expected_sha256: digest(@html),
      allowed_connect_domains: ["https://api.example.test"],
      allowed_resource_domains: ["https://cdn.example.test"],
      allowed_app_domains: ["review.example.test"],
      allowed_permissions: [:clipboardWrite]
    ]

    assert {:ok, verified} = AppResource.verify(resource, opts)
    assert verified.domain == "review.example.test"
    assert verified.prefers_border

    assert AppResource.verify(resource, Keyword.put(opts, :allowed_app_domains, [])) ==
             {:error, :domain_not_allowed}

    invalid_origin =
      put_in(resource, ["_meta", "ui", "csp", "connectDomains"], [
        "https://api.example.test/path"
      ])

    assert AppResource.verify(invalid_origin, opts) == {:error, :invalid_app_resource}

    host_defined_domain = put_in(resource, ["_meta", "ui", "domain"], "https://host/value")

    assert {:ok, verified} =
             AppResource.verify(
               host_defined_domain,
               Keyword.put(opts, :allowed_app_domains, ["https://host/value"])
             )

    assert verified.domain == "https://host/value"
  end

  test "fails closed across malformed content, allowlists, metadata, and options" do
    assert AppResource.verify(%{}, []) == {:error, :invalid_app_resource}
    assert AppResource.verify("not a resource", []) == {:error, :invalid_app_resource}

    assert AppResource.verify(Map.put(resource(), "blob", Base.encode64(@html)),
             expected_sha256: digest(@html)
           ) == {:error, :invalid_app_resource}

    assert AppResource.verify(Map.delete(resource(), "text"),
             expected_sha256: digest(@html)
           ) == {:error, :invalid_app_resource}

    assert AppResource.verify(resource(),
             expected_sha256: digest(@html),
             allowed_connect_domains: :invalid
           ) == {:error, :invalid_options}

    assert AppResource.verify(resource(),
             expected_uri: 123,
             expected_sha256: digest(@html)
           ) == {:error, :invalid_options}

    assert AppResource.verify(resource(),
             expected_sha256: 123
           ) == {:error, :invalid_options}

    assert AppResource.verify(resource(),
             expected_sha256: digest(@html),
             allowed_connect_domains: ["https://api.example.test"],
             allowed_resource_domains: ["https://cdn.example.test"],
             allowed_permissions: [123]
           ) == {:error, :invalid_options}

    assert AppResource.verify(resource(),
             expected_sha256: digest(@html),
             allowed_permissions: :invalid
           ) == {:error, :invalid_options}

    assert AppResource.verify(resource(),
             expected_sha256: digest(@html),
             unknown_option: true
           ) == {:error, :invalid_options}

    assert AppResource.verify(resource(),
             expected_sha256: digest(@html),
             require_digest: true,
             require_digest: false
           ) == {:error, :invalid_options}

    unknown_ui_key = put_in(resource(), ["_meta", "ui", "unknown"], true)

    assert AppResource.verify(unknown_ui_key, expected_sha256: digest(@html)) ==
             {:error, :invalid_app_resource}

    malformed_domain = put_in(resource(), ["_meta", "ui", "domain"], "bad\r\norigin")

    assert AppResource.verify(malformed_domain,
             expected_sha256: digest(@html),
             allowed_app_domains: ["review.example.test"],
             allowed_connect_domains: ["https://api.example.test"],
             allowed_resource_domains: ["https://cdn.example.test"],
             allowed_permissions: [:clipboardWrite]
           ) == {:error, :invalid_app_resource}
  end

  test "bounds rendered bytes and rejects invalid UTF-8" do
    opts = [
      expected_uri: "ui://repo/review",
      expected_sha256: digest(@html),
      max_bytes: byte_size(@html) - 1,
      allowed_connect_domains: ["https://api.example.test"],
      allowed_resource_domains: ["https://cdn.example.test"],
      allowed_permissions: [:clipboardWrite]
    ]

    assert AppResource.verify(resource(), opts) == {:error, :resource_too_large}

    invalid_utf8 =
      resource()
      |> Map.delete("text")
      |> Map.put("blob", Base.encode64(<<255, 254>>))

    assert AppResource.verify(
             invalid_utf8,
             Keyword.put(opts, :expected_sha256, digest(<<255, 254>>))
           ) == {:error, :invalid_app_resource}
  end

  test "applies the default one-mebibyte resource limit" do
    at_limit = String.duplicate("a", 1_048_576)
    over_limit = at_limit <> "a"

    base = %{
      "uri" => "ui://repo/large",
      "mimeType" => "text/html;profile=mcp-app"
    }

    assert {:ok, _} =
             base
             |> Map.put("text", at_limit)
             |> AppResource.verify(expected_sha256: digest(at_limit))

    assert base
           |> Map.put("text", over_limit)
           |> AppResource.verify(expected_sha256: digest(over_limit)) ==
             {:error, :resource_too_large}
  end

  test "accepts only valid, directive-specific CSP origins" do
    wildcard_resource =
      put_in(resource(), ["_meta", "ui", "csp"], %{
        "resourceDomains" => ["https://*.example.test"]
      })

    assert {:ok, _} =
             AppResource.verify(wildcard_resource,
               expected_sha256: digest(@html),
               allowed_resource_domains: ["https://*.example.test"],
               allowed_permissions: [:clipboardWrite]
             )

    wildcard_connect =
      put_in(resource(), ["_meta", "ui", "csp"], %{
        "connectDomains" => ["https://*.example.test"]
      })

    assert AppResource.verify(wildcard_connect,
             expected_sha256: digest(@html),
             allowed_connect_domains: ["https://api.example.test"],
             allowed_permissions: [:clipboardWrite]
           ) == {:error, :invalid_app_resource}

    malformed_wildcard =
      put_in(resource(), ["_meta", "ui", "csp"], %{
        "resourceDomains" => ["https://*.*.example.test"]
      })

    assert AppResource.verify(malformed_wildcard,
             expected_sha256: digest(@html),
             allowed_resource_domains: ["https://cdn.example.test"],
             allowed_permissions: [:clipboardWrite]
           ) == {:error, :invalid_app_resource}

    malformed_uri =
      put_in(resource(), ["_meta", "ui", "csp"], %{
        "resourceDomains" => ["https://["]
      })

    assert AppResource.verify(malformed_uri,
             expected_sha256: digest(@html),
             allowed_resource_domains: ["https://cdn.example.test"],
             allowed_permissions: [:clipboardWrite]
           ) == {:error, :invalid_app_resource}
  end

  test "rejects ambiguous atom and string representations" do
    ambiguous_resource = Map.put(resource(), :uri, "ui://other")

    assert AppResource.verify(ambiguous_resource,
             expected_sha256: digest(@html),
             allowed_connect_domains: ["https://api.example.test"],
             allowed_resource_domains: ["https://cdn.example.test"],
             allowed_permissions: [:clipboardWrite]
           ) == {:error, :invalid_app_resource}

    ambiguous_ui =
      put_in(resource(), ["_meta", "ui", :permissions], %{clipboardWrite: %{}})

    assert AppResource.verify(ambiguous_ui,
             expected_sha256: digest(@html),
             allowed_connect_domains: ["https://api.example.test"],
             allowed_resource_domains: ["https://cdn.example.test"],
             allowed_permissions: [:clipboardWrite]
           ) == {:error, :invalid_app_resource}
  end

  defp resource do
    %{
      "uri" => "ui://repo/review",
      "mimeType" => "text/html;profile=mcp-app",
      "text" => @html,
      "_meta" => %{
        "ui" => %{
          "csp" => %{
            "connectDomains" => ["https://api.example.test"],
            "resourceDomains" => ["https://cdn.example.test"]
          },
          "permissions" => %{"clipboardWrite" => %{}}
        }
      }
    }
  end

  defp digest(content) do
    content
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end
end
