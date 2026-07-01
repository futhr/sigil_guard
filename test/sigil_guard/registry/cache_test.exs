defmodule SigilGuard.Registry.CacheTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Registry.Bundle
  alias SigilGuard.Registry.Cache
  alias SigilGuard.TestSigner

  @moduletag :capture_log
  @registry_issuer "did:sigil:registry"

  setup do
    bypass = Bypass.open()
    start_supervised!({Finch, name: SigilGuard.Finch})

    # Configure registry URL to point to bypass
    Application.put_env(:sigil_guard, :registry_url, "http://localhost:#{bypass.port}")

    on_exit(fn ->
      Application.delete_env(:sigil_guard, :registry_url)
    end)

    %{bypass: bypass}
  end

  describe "startup fetch" do
    test "fetches patterns on startup and merges with built-in", %{bypass: bypass} do
      bundle = %{
        "patterns" => [
          %{
            "name" => "registry_pat",
            "regex" => "REG_\\d+",
            "category" => "test",
            "severity" => "high"
          }
        ]
      }

      Bypass.expect(bypass, "GET", "/patterns/bundle", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(bundle))
      end)

      pid = start_supervised!({Cache, ttl_ms: 600_000})

      # Give async fetch time to complete
      Process.sleep(100)
      assert is_pid(pid)

      patterns = Cache.patterns()
      names = Enum.map(patterns, & &1.name)

      assert "registry_pat" in names
      # Built-in patterns should also be present
      assert "aws_access_key" in names
    end

    test "falls back to built-in patterns when fetch fails", %{bypass: bypass} do
      Bypass.expect(bypass, "GET", "/patterns/bundle", fn conn ->
        Plug.Conn.resp(conn, 500, "error")
      end)

      start_supervised!({Cache, ttl_ms: 600_000})
      Process.sleep(100)

      assert Cache.source() == :fallback
      patterns = Cache.patterns()
      assert length(patterns) > 0
    end
  end

  describe "source tracking" do
    test "reports :registry after successful fetch", %{bypass: bypass} do
      bundle = %{
        "patterns" => [%{"name" => "x", "regex" => "x", "category" => "t", "severity" => "low"}]
      }

      Bypass.expect(bypass, "GET", "/patterns/bundle", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(bundle))
      end)

      start_supervised!({Cache, ttl_ms: 600_000})
      Process.sleep(100)

      assert Cache.source() == :registry
    end
  end

  describe "bundle provenance" do
    test "loads signed bundles when signatures are required", %{bypass: bypass} do
      bundle =
        registry_bundle([
          %{"name" => "signed", "regex" => "SIGNED", "category" => "t", "severity" => "low"}
        ])

      signed = signed_bundle(bundle)

      Bypass.expect(bypass, "GET", "/patterns/bundle", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(signed))
      end)

      start_supervised!(
        {Cache,
         ttl_ms: 600_000,
         require_signed_bundles: true,
         bundle_public_keys: %{@registry_issuer => TestSigner.public_key_b64u()}}
      )

      Process.sleep(100)

      assert Cache.source() == :registry
      assert "signed" in pattern_names()

      status = Cache.status()
      assert status.bundle_provenance["issuer"] == @registry_issuer
      assert is_binary(status.bundle_digest)
      assert status.quarantine == nil
    end

    test "quarantines unsigned bundles when signatures are required", %{bypass: bypass} do
      bundle =
        registry_bundle([
          %{"name" => "unsigned", "regex" => "UNSIGNED", "category" => "t", "severity" => "low"}
        ])

      Bypass.expect(bypass, "GET", "/patterns/bundle", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(bundle))
      end)

      start_supervised!(
        {Cache,
         ttl_ms: 600_000,
         require_signed_bundles: true,
         bundle_public_keys: %{@registry_issuer => TestSigner.public_key_b64u()}}
      )

      Process.sleep(100)

      assert Cache.source() == :quarantine
      refute "unsigned" in pattern_names()
      assert "aws_access_key" in pattern_names()

      status = Cache.status()
      assert status.quarantine.reason == :unsigned_bundle
    end

    test "quarantines tampered bundles and retains the previous known-good patterns", %{
      bypass: bypass
    } do
      call_count = :counters.new(1, [:atomics])

      Bypass.expect(bypass, "GET", "/patterns/bundle", fn conn ->
        :counters.add(call_count, 1, 1)

        bundle =
          case :counters.get(call_count, 1) do
            1 ->
              registry_bundle([
                %{"name" => "initial", "regex" => "INIT", "category" => "t", "severity" => "low"}
              ])
              |> signed_bundle()

            _ ->
              registry_bundle([
                %{
                  "name" => "tampered",
                  "regex" => "TAMPERED",
                  "category" => "t",
                  "severity" => "high"
                }
              ])
              |> signed_bundle()
              |> put_in(["patterns"], [
                %{
                  "name" => "evil",
                  "regex" => "EVIL",
                  "category" => "t",
                  "severity" => "critical"
                }
              ])
          end

        Plug.Conn.resp(conn, 200, Jason.encode!(bundle))
      end)

      start_supervised!(
        {Cache,
         ttl_ms: 600_000,
         require_signed_bundles: true,
         bundle_public_keys: %{@registry_issuer => TestSigner.public_key_b64u()}}
      )

      Process.sleep(100)

      assert Cache.source() == :registry
      assert "initial" in pattern_names()

      Cache.refresh()
      Process.sleep(100)

      assert Cache.source() == :quarantine
      assert "initial" in pattern_names()
      refute "evil" in pattern_names()

      status = Cache.status()
      assert status.quarantine.reason == :digest_mismatch
    end

    test "quarantines stale signed bundles when maximum age is configured", %{bypass: bypass} do
      stale =
        registry_bundle([
          %{"name" => "stale", "regex" => "STALE", "category" => "t", "severity" => "low"}
        ])
        |> signed_bundle(issued_at: "2020-01-01T00:00:00.000Z")

      Bypass.expect(bypass, "GET", "/patterns/bundle", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(stale))
      end)

      start_supervised!(
        {Cache,
         ttl_ms: 600_000,
         require_signed_bundles: true,
         bundle_public_keys: %{@registry_issuer => TestSigner.public_key_b64u()},
         bundle_max_age_seconds: 600}
      )

      Process.sleep(100)

      assert Cache.source() == :quarantine
      refute "stale" in pattern_names()
      assert "aws_access_key" in pattern_names()

      status = Cache.status()
      assert status.quarantine.reason == :stale_bundle
      assert status.quarantine.issuer == @registry_issuer
    end

    test "retains previous known-good patterns when a refresh fetches a stale signed bundle", %{
      bypass: bypass
    } do
      call_count = :counters.new(1, [:atomics])

      Bypass.expect(bypass, "GET", "/patterns/bundle", fn conn ->
        :counters.add(call_count, 1, 1)

        bundle =
          case :counters.get(call_count, 1) do
            1 ->
              registry_bundle([
                %{"name" => "fresh", "regex" => "FRESH", "category" => "t", "severity" => "low"}
              ])
              |> signed_bundle(issued_at: DateTime.utc_now(:millisecond) |> DateTime.to_iso8601())

            _ ->
              registry_bundle([
                %{"name" => "stale", "regex" => "STALE", "category" => "t", "severity" => "high"}
              ])
              |> signed_bundle(issued_at: "2020-01-01T00:00:00.000Z")
          end

        Plug.Conn.resp(conn, 200, Jason.encode!(bundle))
      end)

      start_supervised!(
        {Cache,
         ttl_ms: 600_000,
         require_signed_bundles: true,
         bundle_public_keys: %{@registry_issuer => TestSigner.public_key_b64u()},
         bundle_max_age_seconds: 600}
      )

      Process.sleep(100)

      assert Cache.source() == :registry
      assert "fresh" in pattern_names()

      Cache.refresh()
      Process.sleep(100)

      assert Cache.source() == :quarantine
      assert "fresh" in pattern_names()
      refute "stale" in pattern_names()

      status = Cache.status()
      assert status.quarantine.reason == :stale_bundle
    end
  end

  describe "rule_count/0" do
    test "returns count of cached patterns", %{bypass: bypass} do
      bundle = %{
        "patterns" => [
          %{"name" => "a", "regex" => "a", "category" => "t", "severity" => "low"},
          %{"name" => "b", "regex" => "b", "category" => "t", "severity" => "low"}
        ]
      }

      Bypass.expect(bypass, "GET", "/patterns/bundle", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(bundle))
      end)

      start_supervised!({Cache, ttl_ms: 600_000})
      Process.sleep(100)

      # 6 built-in + 2 registry = 8
      assert Cache.rule_count() == 8
    end
  end

  describe "invalid bundle handling" do
    test "falls back when registry returns invalid bundle format", %{bypass: bypass} do
      # Return a 200 with valid JSON but invalid bundle structure (no "patterns" key)
      Bypass.expect(bypass, "GET", "/patterns/bundle", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"data" => "not_patterns"}))
      end)

      start_supervised!({Cache, ttl_ms: 600_000})
      Process.sleep(100)

      # Should fall back to built-in patterns since this is empty state
      assert Cache.source() == :fallback
      patterns = Cache.patterns()
      assert length(patterns) > 0
    end

    test "retains previous patterns on re-fetch failure", %{bypass: bypass} do
      call_count = :counters.new(1, [:atomics])

      Bypass.expect(bypass, "GET", "/patterns/bundle", fn conn ->
        :counters.add(call_count, 1, 1)
        current = :counters.get(call_count, 1)

        if current <= 1 do
          # First call succeeds
          bundle = %{
            "patterns" => [
              %{"name" => "initial", "regex" => "INIT", "category" => "t", "severity" => "low"}
            ]
          }

          Plug.Conn.resp(conn, 200, Jason.encode!(bundle))
        else
          # Subsequent calls fail
          Plug.Conn.resp(conn, 500, "error")
        end
      end)

      start_supervised!({Cache, ttl_ms: 600_000})
      Process.sleep(100)

      assert Cache.source() == :registry
      initial_count = Cache.rule_count()

      # Force refresh — will fail, should keep existing patterns
      Cache.refresh()
      Process.sleep(100)

      assert Cache.source() == :fallback
      assert Cache.rule_count() == initial_count
    end
  end

  describe "patterns/0" do
    test "returns built-in patterns when source is :empty", %{bypass: bypass} do
      Bypass.expect(bypass, "GET", "/patterns/bundle", fn conn ->
        Plug.Conn.resp(conn, 500, "error")
      end)

      start_supervised!({Cache, ttl_ms: 600_000})
      Process.sleep(100)

      # Force source back to :empty to test the built-in fallback in handle_call
      :sys.replace_state(Cache, fn state -> %{state | source: :empty, patterns: []} end)

      patterns = Cache.patterns()
      assert length(patterns) > 0
      names = Enum.map(patterns, & &1.name)
      assert "aws_access_key" in names
    end
  end

  describe "failure retry" do
    test "retries a failed fetch after retry_ms instead of waiting the TTL", %{bypass: bypass} do
      call_count = :counters.new(1, [:atomics])

      Bypass.expect(bypass, "GET", "/patterns/bundle", fn conn ->
        :counters.add(call_count, 1, 1)

        if :counters.get(call_count, 1) == 1 do
          Plug.Conn.resp(conn, 500, "error")
        else
          bundle = %{
            "patterns" => [
              %{"name" => "late", "regex" => "LATE", "category" => "t", "severity" => "low"}
            ]
          }

          Plug.Conn.resp(conn, 200, Jason.encode!(bundle))
        end
      end)

      start_supervised!({Cache, ttl_ms: 600_000, retry_ms: 150})
      Process.sleep(100)

      # First fetch failed; retry has not fired yet
      assert Cache.source() == :fallback

      # The retry fires at retry_ms (150ms), far before the 10-minute TTL
      Process.sleep(200)
      assert Cache.source() == :registry
      assert "late" in Enum.map(Cache.patterns(), & &1.name)
    end
  end

  describe "refresh/0" do
    test "forces a re-fetch", %{bypass: bypass} do
      call_count = :counters.new(1, [:atomics])

      Bypass.expect(bypass, "GET", "/patterns/bundle", fn conn ->
        :counters.add(call_count, 1, 1)

        bundle = %{
          "patterns" => [%{"name" => "x", "regex" => "x", "category" => "t", "severity" => "low"}]
        }

        Plug.Conn.resp(conn, 200, Jason.encode!(bundle))
      end)

      start_supervised!({Cache, ttl_ms: 600_000})
      Process.sleep(100)

      Cache.refresh()
      Process.sleep(100)

      assert :counters.get(call_count, 1) >= 2
    end
  end

  defp registry_bundle(patterns), do: %{"patterns" => patterns}

  defp signed_bundle(bundle, opts \\ []) do
    Bundle.sign(bundle, TestSigner,
      issuer: @registry_issuer,
      issued_at: Keyword.get(opts, :issued_at, "2026-06-30T12:00:00.000Z")
    )
  end

  defp pattern_names do
    Cache.patterns()
    |> Enum.map(& &1.name)
  end
end
