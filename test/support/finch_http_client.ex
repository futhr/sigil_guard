defmodule SigilGuard.FinchHTTPClient do
  @moduledoc false
  # Reference/test `SigilGuard.HTTPClient` adapter over Finch. Ships as a test
  # support module only; hosts provide their own client in production.

  @behaviour SigilGuard.HTTPClient

  @impl SigilGuard.HTTPClient
  def request(method, url, headers, body, opts) do
    timeout = Keyword.get(opts, :timeout, 5_000)
    finch_request = Finch.build(method, url, headers, body)

    case Finch.request(finch_request, SigilGuard.Finch, receive_timeout: timeout) do
      {:ok, %Finch.Response{status: status, headers: response_headers, body: response_body}} ->
        {:ok, %{status: status, headers: response_headers, body: response_body}}

      {:error, %{reason: reason}} when is_atom(reason) ->
        {:error, reason}

      {:error, _} ->
        {:error, :request_failed}
    end
  end
end
