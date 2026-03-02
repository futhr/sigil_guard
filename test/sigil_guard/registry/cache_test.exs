defmodule SigilGuard.Registry.CacheTest do
  @moduledoc """
  Tests for `SigilGuard.Registry.Cache`.

  Exercises the GenServer TTL cache lifecycle: initial fetch, cache hits,
  TTL expiry and refresh, fallback to stale data on fetch failure, and
  source tracking (`:registry`, `:cache`, `:fallback`, `:empty`).
  """

  use ExUnit.Case, async: false

  alias SigilGuard.Registry.Cache

  @moduletag :capture_log

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
end
