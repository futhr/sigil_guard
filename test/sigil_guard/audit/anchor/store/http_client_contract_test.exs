defmodule SigilGuard.Audit.Anchor.Store.HTTPClientContractTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Audit
  alias SigilGuard.Audit.Anchor
  alias SigilGuard.Audit.Anchor.Store
  alias SigilGuard.Audit.Anchor.Store.HTTP
  alias SigilGuard.Audit.Checkpoint

  @secret_key :crypto.hash(:sha256, "http client contract test key")
  @generated_at "2026-01-01T00:00:00.000Z"

  defmodule ErrorClient do
    @moduledoc false
    @behaviour SigilGuard.HTTPClient
    @impl SigilGuard.HTTPClient
    def request(_, _, _, _, _), do: {:error, :boom}
  end

  defmodule CrashClient do
    @moduledoc false
    @behaviour SigilGuard.HTTPClient
    @impl SigilGuard.HTTPClient
    def request(_, _, _, _, _), do: raise("adapter exploded")
  end

  defmodule BigBodyClient do
    @moduledoc false
    @behaviour SigilGuard.HTTPClient
    @impl SigilGuard.HTTPClient
    def request(_, _, _, _, _) do
      {:ok, %{status: 200, headers: [], body: String.duplicate("x", 5_000)}}
    end
  end

  defmodule MangledClient do
    @moduledoc false
    @behaviour SigilGuard.HTTPClient
    @impl SigilGuard.HTTPClient
    def request(_, _, _, _, _) do
      {:ok, %{status: 200, headers: [], body: "definitely not json"}}
    end
  end

  defmodule NoStatusClient do
    @moduledoc false
    @behaviour SigilGuard.HTTPClient
    @impl SigilGuard.HTTPClient
    def request(_, _, _, _, _), do: {:ok, %{body: "{}"}}
  end

  defmodule TimeoutClient do
    @moduledoc false
    @behaviour SigilGuard.HTTPClient
    @impl SigilGuard.HTTPClient
    def request(_, _, _, _, opts) do
      Process.put(:captured_timeout, opts[:timeout])
      {:ok, %{status: 200, headers: [], body: "{}"}}
    end
  end

  setup do
    Application.delete_env(:sigil_guard, :http_client)
    on_exit(fn -> Application.delete_env(:sigil_guard, :http_client) end)
    %{anchor: anchor()}
  end

  describe "client resolution (D9)" do
    test "no configured client fails :http_client_not_configured", ctx do
      assert Store.put(HTTP, ctx.anchor, url: "http://x/") ==
               {:error, :http_client_not_configured}
    end

    test "a module not exporting request/5 fails :http_client_not_configured", ctx do
      assert Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: String) ==
               {:error, :http_client_not_configured}
    end

    test "the per-call client wins over the app-env client", ctx do
      Application.put_env(:sigil_guard, :http_client, ErrorClient)

      assert Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: CrashClient) ==
               {:error, {:http_client_error, :adapter_crash}}
    end

    test "falls back to the app-env client when no per-call client is given", ctx do
      Application.put_env(:sigil_guard, :http_client, ErrorClient)

      assert Store.put(HTTP, ctx.anchor, url: "http://x/") ==
               {:error, {:http_client_error, :boom}}
    end
  end

  describe "failure surfacing" do
    test "an adapter error surfaces as {:http_client_error, reason}", ctx do
      assert Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: ErrorClient) ==
               {:error, {:http_client_error, :boom}}
    end

    test "an adapter crash surfaces as {:http_client_error, :adapter_crash}", ctx do
      assert Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: CrashClient) ==
               {:error, {:http_client_error, :adapter_crash}}
    end

    test "a response with no status surfaces as an :http_client_error", ctx do
      assert Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: NoStatusClient) ==
               {:error, {:http_client_error, :invalid_response}}
    end
  end

  describe "response guards" do
    test "a body over :max_body_bytes fails :response_too_large", ctx do
      assert Store.put(HTTP, ctx.anchor,
               url: "http://x/",
               http_client: BigBodyClient,
               max_body_bytes: 100
             ) == {:error, :response_too_large}
    end

    test "a mangled (non-JSON) body fails :invalid_body", ctx do
      assert Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: MangledClient) ==
               {:error, :invalid_body}
    end
  end

  describe "timeout" do
    test "the store passes the resolved timeout to the adapter", ctx do
      Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: TimeoutClient, timeout: 1234)
      assert Process.get(:captured_timeout) == 1234

      Store.put(HTTP, ctx.anchor, url: "http://x/", http_client: TimeoutClient)
      assert Process.get(:captured_timeout) == 5_000
    end
  end

  defp anchor do
    events =
      1..2
      |> Enum.map(&Audit.new_event("test", "actor", "act#{&1}", "ok"))
      |> Audit.build_chain(@secret_key)

    {:ok, checkpoint} = Checkpoint.create(events, generated_at: @generated_at)
    Anchor.create(checkpoint, anchored_at: @generated_at, storage: :http, uri: "https://x/1")
  end
end
