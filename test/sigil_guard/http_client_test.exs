defmodule SigilGuard.HTTPClientTest do
  @moduledoc false

  use ExUnit.Case, async: true

  defmodule TestClient do
    @behaviour SigilGuard.HTTPClient

    @impl SigilGuard.HTTPClient
    def request(method, url, headers, body, opts) do
      {:ok, %{status: 200, headers: headers, body: inspect({method, url, body, opts})}}
    end
  end

  test "defines the host HTTP adapter callback contract" do
    assert {:ok, response} =
             TestClient.request(:get, "https://example.test", [], nil, timeout: 10)

    assert response.status == 200
    assert response.body =~ "https://example.test"
  end
end
