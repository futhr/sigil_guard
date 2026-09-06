defmodule SigilGuard.ScannerTest do
  @moduledoc false

  use ExUnit.Case, async: true

  doctest SigilGuard.Scanner

  alias SigilGuard.Scanner

  test "overlapping built-in matches redact once without leaking or crashing" do
    text = "api_key=AKIAIOSFODNN7EXAMPLE"
    assert {:hit, hits} = Scanner.scan(text)
    assert length(hits) == 2
    output = Scanner.redact(text, hits)
    refute output =~ "AKIA"
    assert output == Scanner.redact(text, Enum.reverse(hits))
  end

  test "redaction validates spans and accepts a missing replacement hint" do
    assert Scanner.redact("abc", [%{offset: 0, length: 2}]) == "[REDACTED]c"
    assert_raise ArgumentError, fn -> Scanner.redact("abc", [%{offset: 1, length: 3}]) end

    assert_raise ArgumentError, fn ->
      Scanner.redact("abc", [%{offset: 0, length: 1, replacement_hint: 1}])
    end

    assert Scanner.redact("abc", [%{offset: 0, length: 1}, %{offset: 1, length: 1}]) ==
             "[REDACTED][REDACTED]c"
  end

  describe "scan/2" do
    test "returns {:ok, text} for clean input" do
      assert {:ok, "hello world"} = Scanner.scan("hello world")
    end

    test "detects AWS access keys" do
      assert {:hit, [hit]} = Scanner.scan("key=AKIAIOSFODNN7EXAMPLE")

      assert hit.name == "aws_access_key"
      assert hit.category == :secret
      assert hit.severity == :high
      assert hit.match == "AKIAIOSFODNN7EXAMPLE"
      assert hit.replacement_hint == "[AWS_KEY]"
    end

    test "detects ASIA-prefixed AWS keys (temporary credentials)" do
      assert {:hit, _} = Scanner.scan("ASIA1234567890ABCDEF")
    end

    test "detects generic API key assignments" do
      assert {:hit, hits} = Scanner.scan("api_key=sk_live_abcdef1234567890abcd")
      hit = Enum.find(hits, &(&1.name == "generic_api_key"))

      assert hit
      assert hit.severity == :high
    end

    test "detects bearer tokens" do
      token = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
      assert {:hit, hits} = Scanner.scan("Authorization: #{token}")
      hit = Enum.find(hits, &(&1.name == "bearer_token"))

      assert hit
      assert hit.severity == :high
    end

    test "detects database URIs" do
      assert {:hit, hits} = Scanner.scan("postgres://admin:secret@db.example.com:5432/mydb")
      hit = Enum.find(hits, &(&1.name == "database_uri"))

      assert hit
      assert hit.severity == :high
    end

    test "detects MySQL URIs" do
      assert {:hit, hits} = Scanner.scan("mysql://root:password@localhost/db")

      assert Enum.any?(hits, &(&1.name == "database_uri"))
    end

    test "detects MongoDB URIs" do
      assert {:hit, hits} = Scanner.scan("mongodb://user:pass@cluster.mongodb.net/db")

      assert Enum.any?(hits, &(&1.name == "database_uri"))
    end

    test "detects private key headers" do
      assert {:hit, hits} = Scanner.scan("-----BEGIN RSA PRIVATE KEY-----")
      hit = Enum.find(hits, &(&1.name == "private_key"))

      assert hit
      assert hit.severity == :high
    end

    test "detects EC private keys" do
      assert {:hit, _} = Scanner.scan("-----BEGIN EC PRIVATE KEY-----")
    end

    test "detects OpenSSH private keys" do
      assert {:hit, _} = Scanner.scan("-----BEGIN OPENSSH PRIVATE KEY-----")
    end

    test "detects generic private keys" do
      assert {:hit, _} = Scanner.scan("-----BEGIN PRIVATE KEY-----")
    end

    test "detects generic secret assignments" do
      assert {:hit, hits} = Scanner.scan("secret=mysupersecretsecretvalue")

      assert Enum.any?(hits, &(&1.name == "generic_secret"))
    end

    test "detects password assignments" do
      assert {:hit, hits} = Scanner.scan("password=verylongpassword123")

      assert Enum.any?(hits, &(&1.name == "generic_secret"))
    end

    test "returns multiple hits for text with multiple secrets" do
      text = """
      AWS_KEY=AKIAIOSFODNN7EXAMPLE
      DB_URL=postgres://admin:password@db:5432/app
      """

      assert {:hit, hits} = Scanner.scan(text)
      assert length(hits) >= 2
    end

    test "hits are sorted by offset" do
      text = "secret=abc12345678 and AKIAIOSFODNN7EXAMPLE"
      assert {:hit, hits} = Scanner.scan(text)

      offsets = Enum.map(hits, & &1.offset)
      assert offsets == Enum.sort(offsets)
    end

    test "empty string is clean" do
      assert {:ok, ""} = Scanner.scan("")
    end

    test "accepts custom patterns" do
      custom =
        SigilGuard.Patterns.compile([
          %{name: "custom", category: "test", severity: :low, pattern: "CUSTOM_\\d{4}"}
        ])

      assert {:hit, [hit]} = Scanner.scan("found CUSTOM_1234 here", patterns: custom)
      assert hit.name == "custom"
    end

    test "consumes a resolved bundle secret set" do
      {:ok, %{secret: secret}} =
        SigilGuard.PatternSets.resolve([
          %{"set" => "secret", "name" => "custom_key", "regex" => "XK-[0-9]{6}"}
        ])

      assert {:hit, [hit]} = Scanner.scan("token XK-123456 here", patterns: secret)
      assert hit.name == "custom_key"
    end
  end

  describe "redact/3" do
    test "replaces matched regions with hints" do
      text = "key=AKIAIOSFODNN7EXAMPLE rest"
      {:hit, hits} = Scanner.scan(text)

      redacted = Scanner.redact(text, hits)
      assert String.contains?(redacted, "[AWS_KEY]")
      refute String.contains?(redacted, "AKIAIOSFODNN7EXAMPLE")
      assert String.contains?(redacted, "rest")
    end

    test "uses default replacement when hint is nil" do
      hits = [
        %{
          offset: 0,
          length: 5,
          match: "hello",
          name: "test",
          category: "test",
          severity: :low,
          replacement_hint: nil
        }
      ]

      assert Scanner.redact("hello world", hits) == "[REDACTED] world"
    end

    test "uses custom default replacement" do
      hits = [
        %{
          offset: 0,
          length: 5,
          match: "hello",
          name: "test",
          category: "test",
          severity: :low,
          replacement_hint: nil
        }
      ]

      assert Scanner.redact("hello world", hits, default_replacement: "***") == "*** world"
    end

    test "handles multiple non-overlapping hits" do
      hits = [
        %{
          offset: 0,
          length: 3,
          match: "aaa",
          replacement_hint: "[A]",
          name: "a",
          category: "t",
          severity: :low
        },
        %{
          offset: 4,
          length: 3,
          match: "bbb",
          replacement_hint: "[B]",
          name: "b",
          category: "t",
          severity: :low
        }
      ]

      assert Scanner.redact("aaa bbb ccc", hits) == "[A] [B] ccc"
    end
  end

  describe "scan_and_redact/2" do
    test "returns original text when clean" do
      assert Scanner.scan_and_redact("safe text") == "safe text"
    end

    test "returns redacted text when hits found" do
      text = "key=AKIAIOSFODNN7EXAMPLE"
      result = Scanner.scan_and_redact(text)

      assert String.contains?(result, "[AWS_KEY]")
      refute String.contains?(result, "AKIAIOSFODNN7EXAMPLE")
    end
  end

  describe "malformed options" do
    test "rejects non-keyword option containers consistently" do
      for fun <- [
            fn -> Scanner.scan("safe", [{:patterns}]) end,
            fn -> Scanner.redact("safe", [], [{:default_replacement}]) end,
            fn -> Scanner.scan_and_redact("safe", [{:pipeline}]) end
          ] do
        assert_raise ArgumentError, "options must be a keyword list", fun
      end
    end
  end
end
