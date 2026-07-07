defmodule SigilGuard.TestHTTPClient do
  @moduledoc false

  @behaviour SigilGuard.HTTPClient

  @impl SigilGuard.HTTPClient
  def request(method, url, headers, body, opts) do
    timeout = Keyword.get(opts, :timeout, 5_000)

    with :ok <- ensure_inets_started(),
         {:ok, request} <- build_request(method, url, headers, body),
         {:ok, {{_, status, _}, response_headers, response_body}} <-
           :httpc.request(method, request, http_options(timeout), body_format_options()) do
      {:ok,
       %{
         status: status,
         headers: normalize_headers(response_headers),
         body: IO.iodata_to_binary(response_body)
       }}
    else
      {:error, reason} when is_atom(reason) -> {:error, reason}
      {:error, {reason, _}} when is_atom(reason) -> {:error, reason}
      {:error, _} -> {:error, :request_failed}
    end
  end

  defp ensure_inets_started do
    case Application.ensure_all_started(:inets) do
      {:ok, _} -> :ok
      {:error, _} -> {:error, :inets_unavailable}
    end
  end

  defp build_request(:get, url, headers, nil) do
    {:ok, {String.to_charlist(url), encode_headers(headers)}}
  end

  defp build_request(:post, url, headers, body) when is_binary(body) do
    {content_type, headers} = pop_content_type(headers)
    {:ok, {String.to_charlist(url), encode_headers(headers), content_type, body}}
  end

  defp build_request(_, _, _, _), do: {:error, :unsupported_request}

  defp http_options(:infinity), do: []
  defp http_options(timeout), do: [timeout: timeout]

  defp body_format_options, do: [body_format: :binary]

  defp pop_content_type(headers) do
    {content_type, headers} =
      Enum.reduce(headers, {"application/octet-stream", []}, fn {name, value},
                                                                {content_type, acc} ->
        if String.downcase(name) == "content-type" do
          {value, acc}
        else
          {content_type, [{name, value} | acc]}
        end
      end)

    {String.to_charlist(content_type), Enum.reverse(headers)}
  end

  defp encode_headers(headers) do
    Enum.map(headers, fn {name, value} ->
      {String.to_charlist(name), String.to_charlist(value)}
    end)
  end

  defp normalize_headers(headers) do
    Enum.map(headers, fn {name, value} ->
      {to_string(name), to_string(value)}
    end)
  end
end
