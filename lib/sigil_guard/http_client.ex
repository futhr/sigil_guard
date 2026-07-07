defmodule SigilGuard.HTTPClient do
  @moduledoc """
  Host-provided HTTP client behaviour for audit-anchor integrations.

  SigilGuard performs no HTTP in any scan, gate, policy, or attestation decision
  path (CLAUDE.md rule 8). The single exception is the optional, host-triggered
  audit anchor HTTP store (`SigilGuard.Audit.Anchor.Store.HTTP`), which routes
  every request through a host-provided module implementing this behaviour.

  The store resolves the client per call (`opts[:http_client]`), then from the
  `:sigil_guard` application env (`:http_client`), and otherwise fails closed with
  `{:error, :http_client_not_configured}` at first use - never a silent no-op. It
  passes the resolved `:timeout` (default `5_000` ms; `:infinity` allowed) in
  `opts`, which adapters MUST honor, and performs no retries of its own. A host
  adapter MAY retry internally within the timeout budget.

  A reference Finch adapter and an optional `req`-based client are host concerns;
  the core ships no built-in HTTP client.
  """

  @typedoc "Supported request methods for the anchor store."
  @type method :: :get | :post

  @typedoc "HTTP headers as `{name, value}` string pairs."
  @type headers :: [{String.t(), String.t()}]

  @typedoc "An HTTP response."
  @type response :: %{status: non_neg_integer(), headers: headers(), body: binary()}

  @doc """
  Perform an HTTP request and return the response.

  `opts` carries the store's resolved `:timeout` (and `:max_body_bytes`);
  adapters MUST honor the timeout. Return `{:ok, response}` for any completed
  request (including non-2xx statuses - the store maps those) or
  `{:error, reason}` for a transport failure.
  """
  @callback request(
              method(),
              url :: String.t(),
              headers(),
              body :: binary() | nil,
              opts :: keyword()
            ) :: {:ok, response()} | {:error, atom()}
end
