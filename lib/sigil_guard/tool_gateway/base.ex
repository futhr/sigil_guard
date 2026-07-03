defmodule SigilGuard.ToolGateway.Base do
  @moduledoc """
  Transport-agnostic MCP guard helpers.

  The module accepts MCP-shaped maps, normalizes common request/result fields,
  labels the relevant trust boundary, and delegates enforcement to
  `SigilGuard.Runtime.Gate`. It does not depend on a particular MCP server
  or client package.
  """

  alias SigilGuard.Confirmation
  alias SigilGuard.Context
  alias SigilGuard.Decision
  alias SigilGuard.Envelope
  alias SigilGuard.Runtime
  alias SigilGuard.Telemetry

  @known_context_keys Map.keys(%Context{})
  @guard_metadata_keys [
    :_sigil,
    "_sigil",
    :_sigil_confirmation,
    "_sigil_confirmation",
    :confirmation_token,
    "confirmation_token"
  ]
  @blocked_code -32_001
  @confirm_code -32_002
  @quarantine_code -32_003
  @invalid_payload_field false

  @doc """
  Guard an MCP tool request before execution.

  Common JSON-RPC MCP tool-call shapes are supported, including
  `%{"method" => "tools/call", "params" => %{"name" => tool, "arguments" => args}}`.
  """
  @spec guard_request(term(), Context.t() | map() | keyword(), keyword()) :: Decision.t()
  def guard_request(request, context \\ %{}, opts \\ []) do
    request
    |> gate_payload()
    |> Runtime.Gate.evaluate(request_context(request, context), opts)
  end

  @doc """
  Guard an MCP tool request and return either an allow decision or JSON-RPC error.

  This helper is intended for gateway adapters that need a wire-shaped response
  rather than only a `%SigilGuard.Decision{}`.
  """
  @spec guarded_request(term(), Context.t() | map() | keyword(), keyword()) ::
          {:ok, Decision.t()} | {:error, map(), Decision.t()}
  def guarded_request(request, context \\ %{}, opts \\ []) do
    decision = guard_request(request, context, opts)

    if executable?(decision) do
      {:ok, decision}
    else
      {:error, response_for_decision(decision, request_id(request), opts), decision}
    end
  end

  @doc """
  Issue an action-bound confirmation token for a confirm-required MCP request.

  The token is bound to the same normalized request payload and boundary
  context used by `guard_request/3`, excluding SigilGuard transport metadata
  such as `_sigil` and `_sigil_confirmation`.
  """
  @spec issue_confirmation_token(
          term(),
          Context.t() | map() | keyword(),
          Decision.t(),
          binary(),
          keyword()
        ) ::
          {:ok, String.t()} | {:error, term()}
  def issue_confirmation_token(request, context, %Decision{} = decision, key, opts \\ []) do
    Confirmation.issue(
      gate_payload(request),
      request_context(request, context),
      decision,
      key,
      opts
    )
  end

  @doc """
  Issue an action-bound confirmation token for a signed MCP request.

  `_sigil` is verified first, then the token is bound to the signed identity
  as both actor and identity in the gateway context. This prevents a token
  issued for an unsigned or spoofed context from approving a signed request.
  """
  @spec issue_signed_confirmation_token(
          term(),
          Context.t() | map() | keyword(),
          Decision.t(),
          binary(),
          keyword()
        ) ::
          {:ok, String.t()} | {:error, term()}
  def issue_signed_confirmation_token(request, context, %Decision{} = decision, key, opts \\ []) do
    with {:ok, claims} <- verify_request_envelope(request, opts) do
      issue_confirmation_token(
        request,
        signed_context(context, claims.identity),
        decision,
        key,
        opts
      )
    end
  end

  @doc """
  Issue an action-bound confirmation token for a confirm-required MCP result.

  The token is bound to the same normalized result payload and tool-to-model
  boundary context used by `guard_result/3`. When accepted by
  `guard_confirmed_result/3`, quarantined tool output is released only as the
  sanitized result text.
  """
  @spec issue_result_confirmation_token(
          term(),
          Context.t() | map() | keyword(),
          Decision.t(),
          binary(),
          keyword()
        ) ::
          {:ok, String.t()} | {:error, term()}
  def issue_result_confirmation_token(result, context, %Decision{} = decision, key, opts \\ []) do
    Confirmation.issue(
      gate_payload(result),
      result_context(result, context),
      decision,
      key,
      opts
    )
  end

  @doc """
  Guard an MCP tool request and honor an optional confirmation token.

  If the request does not require confirmation, this behaves like
  `guard_request/3`. If confirmation is required and a token is supplied via
  `:confirmation_token`, `_sigil_confirmation`, or `confirmation_token`, the
  token is verified against the request action digest. Gateway confirmation
  tokens are consumed by default; pass `consume_confirmation: false` to keep
  verification stateless.
  """
  @spec guard_confirmed_request(term(), Context.t() | map() | keyword(), keyword()) ::
          Decision.t()
  def guard_confirmed_request(request, context \\ %{}, opts \\ []) do
    decision = guard_request(request, context, opts)

    maybe_apply_confirmation(decision, request, request_context(request, context), opts)
  end

  @doc """
  Guard a possibly confirmed MCP request and return either an allow decision or JSON-RPC error.
  """
  @spec guarded_confirmed_request(term(), Context.t() | map() | keyword(), keyword()) ::
          {:ok, Decision.t()} | {:error, map(), Decision.t()}
  def guarded_confirmed_request(request, context \\ %{}, opts \\ []) do
    decision = guard_confirmed_request(request, context, opts)

    if executable?(decision) do
      {:ok, decision}
    else
      {:error, response_for_decision(decision, request_id(request), opts), decision}
    end
  end

  @doc """
  Guard a signed MCP tool request and honor an optional confirmation token.

  Envelope verification runs before confirmation verification. A valid
  confirmation token must be bound to the normalized request payload and to
  the signed envelope identity.
  """
  @spec guard_signed_confirmed_request(term(), Context.t() | map() | keyword(), keyword()) ::
          Decision.t()
  def guard_signed_confirmed_request(request, context \\ %{}, opts \\ []) do
    case verify_request_envelope(request, opts) do
      {:ok, claims} ->
        signed = signed_context(context, claims.identity)
        decision = guard_request(request, signed, opts)

        confirmed =
          maybe_apply_confirmation(decision, request, request_context(request, signed), opts)

        emit_signed_request(confirmed, :valid, nil)
        confirmed

      {:error, reason} ->
        envelope_decision(request, context, reason)
    end
  end

  @doc """
  Guard a signed, possibly confirmed MCP request and return either an allow decision or JSON-RPC error.
  """
  @spec guarded_signed_confirmed_request(term(), Context.t() | map() | keyword(), keyword()) ::
          {:ok, Decision.t()} | {:error, map(), Decision.t()}
  def guarded_signed_confirmed_request(request, context \\ %{}, opts \\ []) do
    decision = guard_signed_confirmed_request(request, context, opts)

    if executable?(decision) do
      {:ok, decision}
    else
      {:error, response_for_decision(decision, request_id(request), opts), decision}
    end
  end

  @doc """
  Guard a signed MCP tool request before execution.

  This verifies `_sigil` metadata before the regular runtime gate. `_sigil`
  may be placed on the request itself or inside JSON-RPC `params`.

  Options:

    * `:public_keys` - map of envelope identity to Ed25519 public key.
    * `:public_key_b64u` - fallback public key for any identity.
    * `:max_skew_ms`, `:replay`, `:replay_ttl_ms`, `:profile` - passed to
      `SigilGuard.Envelope.verify/3`.
  """
  @spec guard_signed_request(term(), Context.t() | map() | keyword(), keyword()) :: Decision.t()
  def guard_signed_request(request, context \\ %{}, opts \\ []) do
    case verify_request_envelope(request, opts) do
      {:ok, claims} ->
        decision = guard_request(request, signed_context(context, claims.identity), opts)
        emit_signed_request(decision, :valid, nil)
        decision

      {:error, reason} ->
        envelope_decision(request, context, reason)
    end
  end

  @doc """
  Guard a signed MCP tool request and return either an allow decision or JSON-RPC error.
  """
  @spec guarded_signed_request(term(), Context.t() | map() | keyword(), keyword()) ::
          {:ok, Decision.t()} | {:error, map(), Decision.t()}
  def guarded_signed_request(request, context \\ %{}, opts \\ []) do
    decision = guard_signed_request(request, context, opts)

    if executable?(decision) do
      {:ok, decision}
    else
      {:error, response_for_decision(decision, request_id(request), opts), decision}
    end
  end

  @doc """
  Verify `_sigil` metadata on an MCP request.

  Returns signed identity claims without running the runtime gate.
  """
  @spec verify_request_envelope(term(), keyword()) ::
          {:ok, %{identity: String.t(), envelope: map()}} | {:error, atom()}
  def verify_request_envelope(request, opts \\ []) do
    with {:ok, envelope} <- request_envelope(request),
         {:ok, identity} <- envelope_identity(envelope),
         {:ok, public_key_b64u} <- envelope_public_key(identity, opts),
         :ok <- Envelope.verify(envelope, public_key_b64u, opts) do
      {:ok, %{identity: identity, envelope: envelope}}
    end
  end

  @doc """
  Guard an MCP tool result before model ingestion.
  """
  @spec guard_result(term(), Context.t() | map() | keyword(), keyword()) :: Decision.t()
  def guard_result(result, context \\ %{}, opts \\ []) do
    result
    |> gate_payload()
    |> Runtime.Gate.evaluate(result_context(result, context), opts)
  end

  @doc """
  Guard an MCP tool result and honor an optional confirmation token.

  Confirmed quarantines are released as sanitized JSON-RPC results, never as
  raw tool output. Confirmation tokens are consumed by default; pass
  `consume_confirmation: false` to keep verification stateless.
  """
  @spec guard_confirmed_result(term(), Context.t() | map() | keyword(), keyword()) ::
          Decision.t()
  def guard_confirmed_result(result, context \\ %{}, opts \\ []) do
    decision = guard_result(result, context, opts)

    maybe_apply_result_confirmation(decision, result, result_context(result, context), opts)
  end

  @doc """
  Guard an MCP tool result and return a safe MCP-shaped result or JSON-RPC error.

  Redacted results are returned as JSON-RPC result objects containing sanitized
  text. Blocked, quarantined, or confirmation-required results become JSON-RPC
  errors with audit-safe metadata only.
  """
  @spec guarded_result(term(), Context.t() | map() | keyword(), keyword()) ::
          {:ok, map(), Decision.t()} | {:error, map(), Decision.t()}
  def guarded_result(result, context \\ %{}, opts \\ []) do
    decision = guard_result(result, context, opts)

    case decision.action do
      :allow ->
        {:ok, jsonrpc_result(result, request_id(result)), decision}

      :redact ->
        {:ok, sanitized_result(result, decision, request_id(result)), decision}

      _ ->
        {:error, response_for_decision(decision, request_id(result), opts), decision}
    end
  end

  @doc """
  Guard a possibly confirmed MCP result and return a safe MCP-shaped result or JSON-RPC error.
  """
  @spec guarded_confirmed_result(term(), Context.t() | map() | keyword(), keyword()) ::
          {:ok, map(), Decision.t()} | {:error, map(), Decision.t()}
  def guarded_confirmed_result(result, context \\ %{}, opts \\ []) do
    decision = guard_confirmed_result(result, context, opts)

    case decision.action do
      :allow ->
        {:ok, jsonrpc_result(result, request_id(result)), decision}

      :redact ->
        {:ok, sanitized_result(result, decision, request_id(result)), decision}

      _ ->
        {:error, response_for_decision(decision, request_id(result), opts), decision}
    end
  end

  @doc """
  Start a chunk-safe stream sanitizer for MCP tool results.
  """
  @spec stream_result(Context.t() | map() | keyword(), keyword()) :: Runtime.Stream.t()
  def stream_result(context \\ %{}, opts \\ []) do
    %{}
    |> result_context(context)
    |> Runtime.Stream.new(opts)
  end

  @doc """
  Push one MCP tool-result stream chunk through the gateway sanitizer.

  Returns `{stream, result}` where `result` is:

    * `{:ok, response, decision}` when a safe MCP-shaped chunk can be emitted.
    * `{:ok, nil, decision}` when the chunk is still held back for boundary checks.
    * `{:error, response, decision}` when the stream is blocked or quarantined.

  Pass `id: json_rpc_id` to include the JSON-RPC request id in emitted chunks
  and error responses.
  """
  @spec guarded_result_chunk(Runtime.Stream.t(), String.t(), keyword()) ::
          {Runtime.Stream.t(), {:ok, map() | nil, Decision.t()} | {:error, map(), Decision.t()}}
  def guarded_result_chunk(%Runtime.Stream{} = stream, chunk, opts \\ []) when is_binary(chunk) do
    stream
    |> Runtime.Stream.push(chunk)
    |> stream_response(opts)
  end

  @doc """
  Flush a guarded MCP tool-result stream.

  This applies the same response shape as `guarded_result_chunk/3` to the final
  held-back stream bytes.
  """
  @spec finish_guarded_result_stream(Runtime.Stream.t(), keyword()) ::
          {Runtime.Stream.t(), {:ok, map() | nil, Decision.t()} | {:error, map(), Decision.t()}}
  def finish_guarded_result_stream(%Runtime.Stream{} = stream, opts \\ []) do
    stream
    |> Runtime.Stream.finish()
    |> stream_response(opts)
  end

  @doc """
  Convert a runtime decision into an audit-safe JSON-RPC response.

  The response intentionally omits raw payload text. Metadata includes hashes,
  counts, indicator identifiers, and confirmation digests when available.
  """
  @spec response_for_decision(Decision.t(), term(), keyword()) :: map()
  def response_for_decision(%Decision{} = decision, id \\ nil, opts \\ []) do
    if decision.verdict == :allowed and decision.action in [:allow, :redact] do
      sanitized_result(%{}, decision, id)
    else
      jsonrpc_error(id, error_code(decision), error_message(decision), error_data(decision, opts))
    end
  end

  defp request_context(request, context) do
    tool = tool_name(request)
    action = action_name(request)

    defaults = %{
      phase: :tool_request,
      origin: :model,
      sink: :tool,
      tool: context_field(tool),
      action: action_field(action, tool),
      mcp_server: context_field(mcp_server(request))
    }

    merge_context(defaults, context)
  end

  defp result_context(result, context) do
    tool = tool_name(result)
    action = action_name(result)

    defaults = %{
      phase: :tool_result,
      origin: :tool,
      sink: :model,
      tool: context_field(tool),
      action: action_field(action, tool),
      mcp_server: context_field(mcp_server(result))
    }

    merge_context(defaults, context)
  end

  defp merge_context(defaults, context) do
    context
    |> context_overrides()
    |> then(&Map.merge(defaults, &1))
    |> Context.new()
  end

  defp signed_context(context, identity) do
    context
    |> context_overrides()
    |> Map.put(:identity, identity)
    |> Map.put(:actor, identity)
  end

  defp context_overrides(%Context{} = context), do: Map.from_struct(context)

  defp context_overrides(context) when is_list(context) do
    context
    |> Map.new()
    |> context_overrides()
  end

  defp context_overrides(context) when is_map(context) do
    Map.new(context, fn {key, value} -> {known_context_key(key), value} end)
  end

  defp context_overrides(_), do: %{}

  defp known_context_key(key) when is_atom(key), do: key

  defp known_context_key(key) when is_binary(key) do
    atom_key = String.to_existing_atom(key)

    if atom_key in @known_context_keys, do: atom_key, else: key
  rescue
    ArgumentError -> key
  end

  defp gate_payload(payload) do
    payload = strip_guard_metadata(payload)
    tool = tool_name(payload)
    action = action_name(payload)

    %{
      tool: context_field(tool),
      action: action_field(action, tool),
      text: text_payload(payload)
    }
  end

  defp strip_guard_metadata(value) when is_map(value) do
    value
    |> Map.drop(@guard_metadata_keys)
    |> strip_params_metadata(:params)
    |> strip_params_metadata("params")
  end

  defp strip_guard_metadata(value), do: value

  defp strip_params_metadata(payload, params_key) do
    case Map.get(payload, params_key) do
      params when is_map(params) ->
        Map.put(payload, params_key, Map.drop(params, @guard_metadata_keys))

      _ ->
        payload
    end
  end

  defp text_payload(payload) when is_map(payload), do: joined_strings(payload)
  defp text_payload(payload), do: Context.text(payload) || joined_strings(payload)

  defp joined_strings(payload) do
    payload
    |> collect_strings()
    |> Enum.reverse()
    |> Enum.join("\n")
  end

  defp collect_strings(value), do: collect_strings(value, [])

  defp collect_strings(value, acc) when is_binary(value), do: [value | acc]

  defp collect_strings(value, acc) when is_list(value) do
    Enum.reduce(value, acc, &collect_strings/2)
  end

  defp collect_strings(value, acc) when is_map(value) do
    value
    |> Map.values()
    |> Enum.reduce(acc, &collect_strings/2)
  end

  defp collect_strings(_, acc), do: acc

  defp tool_name(payload) do
    first_payload_value(payload, [
      [:tool],
      ["tool"],
      [:name],
      ["name"],
      [:params, :name],
      [:params, "name"],
      ["params", :name],
      ["params", "name"]
    ])
  end

  defp action_name(payload) do
    first_payload_value(payload, [
      [:action],
      ["action"],
      [:tool],
      ["tool"],
      [:name],
      ["name"],
      [:params, :name],
      [:params, "name"],
      ["params", :name],
      ["params", "name"],
      [:method],
      ["method"]
    ])
  end

  defp mcp_server(payload) do
    first_payload_value(payload, [
      [:mcp_server],
      ["mcp_server"],
      [:server],
      ["server"],
      [:params, :server],
      [:params, "server"],
      ["params", :server],
      ["params", "server"]
    ])
  end

  defp first_payload_value(payload, paths) when is_map(payload) do
    Enum.reduce_while(paths, nil, fn path, nil ->
      case fetch_path(payload, path) do
        {:ok, nil} -> {:cont, nil}
        {:ok, value} when is_binary(value) -> {:halt, value}
        {:ok, _} -> {:halt, @invalid_payload_field}
        :error -> {:cont, nil}
      end
    end)
  end

  defp first_payload_value(_, _), do: nil

  defp fetch_path(payload, [key]) when is_map(payload), do: Map.fetch(payload, key)

  defp fetch_path(payload, [key | rest]) when is_map(payload) do
    case Map.fetch(payload, key) do
      {:ok, value} when is_map(value) -> fetch_path(value, rest)
      {:ok, nil} -> :error
      {:ok, _} -> {:ok, @invalid_payload_field}
      :error -> :error
    end
  end

  defp fetch_path(_, _), do: :error

  defp action_field(action, tool) do
    if invalid_payload_field?(action) or invalid_payload_field?(tool) do
      @invalid_payload_field
    else
      action
    end
  end

  defp context_field(value) do
    if invalid_payload_field?(value), do: nil, else: value
  end

  defp invalid_payload_field?(@invalid_payload_field), do: true
  defp invalid_payload_field?(_), do: false

  defp executable?(%Decision{verdict: :allowed, action: action}), do: action in [:allow, :redact]
  defp executable?(%Decision{}), do: false

  defp maybe_apply_confirmation(
         %Decision{verdict: {:confirm, _}} = decision,
         request,
         context,
         opts
       ) do
    case confirmation_token(request, opts) do
      {:ok, token} ->
        verify_confirmation_token(decision, request, context, token, opts)

      {:error, :missing_confirmation_token} ->
        decision

      {:error, reason} ->
        confirmation_failure_decision(decision, reason)
    end
  end

  defp maybe_apply_confirmation(%Decision{} = decision, _, _, _), do: decision

  defp maybe_apply_result_confirmation(
         %Decision{verdict: {:confirm, _}} = decision,
         result,
         context,
         opts
       ) do
    decision
    |> maybe_apply_confirmation(result, context, opts)
    |> release_confirmed_result()
  end

  defp maybe_apply_result_confirmation(%Decision{} = decision, _, _, _), do: decision

  defp verify_confirmation_token(decision, request, context, token, opts) do
    with {:ok, key} <- confirmation_key(opts),
         {:ok, claims} <-
           Confirmation.verify(
             token,
             gate_payload(request),
             context,
             key,
             confirmation_opts(opts)
           ) do
      confirmed_decision(decision, claims)
    else
      {:error, reason} -> confirmation_failure_decision(decision, reason)
    end
  end

  defp confirmation_key(opts) do
    case Keyword.get(opts, :confirmation_key) do
      key when is_binary(key) -> {:ok, key}
      _ -> {:error, :missing_confirmation_key}
    end
  end

  defp confirmation_opts(opts) do
    opts
    |> Keyword.take([:now])
    |> Keyword.put(:consume, Keyword.get(opts, :consume_confirmation, true))
  end

  defp confirmed_decision(%Decision{} = decision, claims) do
    metadata =
      Map.merge(decision.audit_metadata, %{
        verdict: :allowed,
        confirmation_status: :accepted,
        confirmation_actor: claims["actor"],
        confirmation_nonce_hash: hash_text(claims["nonce"]),
        confirmation_issued_at: claims["issued_at"],
        confirmation_expires_at: claims["expires_at"]
      })

    %{
      decision
      | verdict: :allowed,
        reason: "Confirmation token accepted",
        audit_metadata: metadata
    }
  end

  defp release_confirmed_result(
         %Decision{
           verdict: :allowed,
           action: :quarantine,
           audit_metadata: metadata
         } = decision
       ) do
    released_metadata =
      Map.merge(metadata, %{
        action: :redact,
        release_status: :confirmed_sanitized
      })

    %{
      decision
      | action: :redact,
        reason: "Confirmation token accepted; sanitized result released",
        audit_metadata: released_metadata
    }
  end

  defp release_confirmed_result(%Decision{} = decision), do: decision

  defp stream_response({%Runtime.Stream{} = stream, %Decision{} = decision, emitted}, opts) do
    id = Keyword.get(opts, :id)

    result =
      if executable?(decision) do
        {:ok, stream_chunk_response(emitted, id), decision}
      else
        {:error, response_for_decision(decision, id, opts), decision}
      end

    {stream, result}
  end

  defp stream_chunk_response("", _), do: nil

  defp stream_chunk_response(text, id) do
    %{
      "jsonrpc" => "2.0",
      "id" => id,
      "result" => %{
        "content" => [
          %{"type" => "text", "text" => text}
        ]
      }
    }
  end

  defp confirmation_failure_decision(%Decision{} = decision, reason) do
    metadata =
      Map.merge(decision.audit_metadata, %{
        verdict: :blocked,
        action: :block,
        risk_level: :high,
        confirmation_status: :invalid,
        confirmation_reason: reason
      })

    %{
      decision
      | verdict: :blocked,
        action: :block,
        reason: "MCP confirmation verification failed: #{format_reason(reason)}",
        risk_level: :high,
        audit_metadata: metadata
    }
  end

  defp request_id(payload) when is_map(payload) do
    first_payload_term(payload, [
      [:id],
      ["id"],
      [:request_id],
      ["request_id"]
    ])
  end

  defp request_id(_), do: nil

  defp confirmation_token_option(opts) do
    case Keyword.fetch(opts, :confirmation_token) do
      {:ok, token} when is_binary(token) -> {:ok, token}
      {:ok, _} -> {:error, :invalid_confirmation_token}
      :error -> :not_found
    end
  end

  defp request_confirmation_token(payload) when is_map(payload) do
    case first_present_payload_term(payload, confirmation_token_paths()) do
      {:ok, token} when is_binary(token) -> {:ok, token}
      {:ok, _} -> {:error, :invalid_confirmation_token}
      :not_found -> {:error, :missing_confirmation_token}
    end
  end

  defp request_confirmation_token(_), do: {:error, :missing_confirmation_token}

  defp confirmation_token(request, opts) do
    case confirmation_token_option(opts) do
      :not_found -> request_confirmation_token(request)
      result -> result
    end
  end

  defp confirmation_token_paths do
    [
      [:_sigil_confirmation],
      ["_sigil_confirmation"],
      [:confirmation_token],
      ["confirmation_token"],
      [:params, :_sigil_confirmation],
      [:params, "_sigil_confirmation"],
      [:params, :confirmation_token],
      [:params, "confirmation_token"],
      ["params", :_sigil_confirmation],
      ["params", "_sigil_confirmation"],
      ["params", :confirmation_token],
      ["params", "confirmation_token"]
    ]
  end

  defp first_payload_term(payload, paths) when is_map(payload) do
    Enum.find_value(paths, &get_in(payload, &1))
  end

  defp first_present_payload_term(payload, paths) when is_map(payload) do
    Enum.reduce_while(paths, :not_found, fn path, :not_found ->
      case fetch_payload_path(payload, path) do
        {:ok, value} -> {:halt, {:ok, value}}
        :error -> {:cont, :not_found}
      end
    end)
  end

  defp fetch_payload_path(payload, []), do: {:ok, payload}

  defp fetch_payload_path(payload, [key | rest]) when is_map(payload) do
    case Map.fetch(payload, key) do
      {:ok, value} -> fetch_payload_path(value, rest)
      :error -> :error
    end
  end

  defp fetch_payload_path(_, _), do: :error

  defp request_envelope(payload) when is_map(payload) do
    case first_present_payload_term(payload, envelope_paths()) do
      {:ok, envelope} when is_map(envelope) -> {:ok, envelope}
      {:ok, _} -> {:error, :invalid_envelope}
      :not_found -> {:error, :missing_envelope}
    end
  end

  defp request_envelope(_), do: {:error, :missing_envelope}

  defp envelope_paths do
    [
      [:_sigil],
      ["_sigil"],
      [:params, :_sigil],
      [:params, "_sigil"],
      ["params", :_sigil],
      ["params", "_sigil"]
    ]
  end

  defp envelope_identity(%{} = envelope) do
    case fetch_field(envelope, "identity", :identity) do
      identity when is_binary(identity) -> {:ok, identity}
      _ -> {:error, :missing_identity}
    end
  end

  defp envelope_public_key(identity, opts) do
    public_keys = Keyword.get(opts, :public_keys, %{})

    if is_map(public_keys) do
      case Map.fetch(public_keys, identity) do
        {:ok, public_key_b64u} when is_binary(public_key_b64u) ->
          {:ok, public_key_b64u}

        {:ok, _} ->
          {:error, :invalid_public_key}

        :error ->
          fallback_public_key(opts)
      end
    else
      {:error, :invalid_public_keys}
    end
  end

  defp fallback_public_key(opts) do
    case Keyword.get(opts, :public_key_b64u) do
      public_key_b64u when is_binary(public_key_b64u) -> {:ok, public_key_b64u}
      _ -> {:error, :unknown_identity}
    end
  end

  defp fetch_field(map, string_key, atom_key) do
    case Map.fetch(map, string_key) do
      {:ok, value} -> value
      :error -> Map.get(map, atom_key)
    end
  end

  defp envelope_decision(request, context, reason) do
    context = request_context(request, context)
    content_hash = hash_text(text_payload(request))

    decision = %Decision{
      verdict: :blocked,
      action: :block,
      reason: "MCP request envelope verification failed: #{format_reason(reason)}",
      phase: context.phase,
      risk_level: :high,
      trust_level: context.trust_level,
      content_hash: content_hash,
      audit_metadata: %{
        phase: context.phase,
        actor: context.actor,
        identity: context.identity,
        origin: context.origin,
        sink: context.sink,
        tool: context.tool,
        mcp_server: context.mcp_server,
        trust_zone: context.trust_zone,
        trust_level: context.trust_level,
        risk_level: :high,
        verdict: :blocked,
        action: :block,
        envelope_status: :invalid,
        envelope_reason: reason,
        content_hash: content_hash
      }
    }

    emit_signed_request(decision, :invalid, reason)
    decision
  end

  defp hash_text(text) do
    :sha256
    |> :crypto.hash(text)
    |> Base.encode16(case: :lower)
  end

  defp format_reason(reason) when is_atom(reason), do: Atom.to_string(reason)

  defp emit_signed_request(%Decision{} = decision, envelope_status, envelope_reason) do
    metadata =
      decision.audit_metadata
      |> Map.take([
        :phase,
        :actor,
        :identity,
        :origin,
        :sink,
        :tool,
        :mcp_server,
        :resource_uri,
        :trust_zone,
        :trust_level,
        :risk_level,
        :verdict,
        :action,
        :hit_count,
        :indicator_count,
        :indicator_ids,
        :content_hash,
        :action_digest,
        :action_digest_error,
        :scanner_error,
        :confirmation_status,
        :confirmation_reason,
        :confirmation_actor,
        :confirmation_nonce_hash,
        :confirmation_issued_at,
        :confirmation_expires_at,
        :repo_policy_verdict,
        :repo_policy_rules,
        :repo_unmatched_paths
      ])
      |> Map.put(:envelope_status, envelope_status)
      |> Map.put(:envelope_reason, envelope_reason)

    Telemetry.emit([:sigil_guard, :mcp, :request], %{system_time: System.system_time()}, metadata)
  end

  defp jsonrpc_result(%{"jsonrpc" => _, "id" => id, "result" => result}, _) do
    %{"jsonrpc" => "2.0", "id" => id, "result" => result}
  end

  defp jsonrpc_result(%{jsonrpc: _, id: id, result: result}, _) do
    %{"jsonrpc" => "2.0", "id" => id, "result" => result}
  end

  defp jsonrpc_result(result, id) do
    %{"jsonrpc" => "2.0", "id" => id, "result" => result}
  end

  defp sanitized_result(result, %Decision{} = decision, id) do
    result
    |> jsonrpc_result(id)
    |> put_in(["result"], sanitized_payload(decision))
  end

  defp sanitized_payload(%Decision{sanitized_text: text}) when is_binary(text) do
    %{
      "content" => [
        %{"type" => "text", "text" => text}
      ]
    }
  end

  defp sanitized_payload(%Decision{}), do: %{"content" => []}

  defp jsonrpc_error(id, code, message, data) do
    %{
      "jsonrpc" => "2.0",
      "id" => id,
      "error" => %{
        "code" => code,
        "message" => message,
        "data" => data
      }
    }
  end

  defp error_code(%Decision{action: :quarantine}), do: @quarantine_code
  defp error_code(%Decision{verdict: {:confirm, _}}), do: @confirm_code
  defp error_code(%Decision{}), do: @blocked_code

  defp error_message(%Decision{action: :quarantine}), do: "SigilGuard quarantined MCP content"
  defp error_message(%Decision{verdict: {:confirm, _}}), do: "SigilGuard requires confirmation"
  defp error_message(%Decision{}), do: "SigilGuard blocked MCP content"

  defp error_data(%Decision{} = decision, opts) do
    base =
      %{
        "status" => error_status(decision),
        "action" => Atom.to_string(decision.action),
        "reason" => decision.reason,
        "phase" => error_value(decision.phase),
        "risk_level" => error_value(decision.risk_level),
        "trust_level" => error_value(decision.trust_level),
        "hit_count" => length(decision.hits),
        "indicator_ids" => Enum.map(decision.indicators, &Atom.to_string(&1.id)),
        "content_hash" => decision.content_hash,
        "action_digest" => decision.audit_metadata[:action_digest],
        "scanner_error" => error_value(decision.audit_metadata[:scanner_error]),
        "confirmation_status" => error_value(decision.audit_metadata[:confirmation_status]),
        "confirmation_reason" => error_value(decision.audit_metadata[:confirmation_reason])
      }
      |> Enum.reject(fn {_, value} -> is_nil(value) end)
      |> Map.new()

    if Keyword.get(opts, :include_sanitized, false) and is_binary(decision.sanitized_text) do
      Map.put(base, "sanitized_text", decision.sanitized_text)
    else
      base
    end
  end

  defp error_status(%Decision{action: :quarantine}), do: "quarantined"
  defp error_status(%Decision{verdict: {:confirm, _}}), do: "confirmation_required"
  defp error_status(%Decision{}), do: "blocked"

  defp error_value(nil), do: nil
  defp error_value(value) when is_atom(value), do: Atom.to_string(value)
  defp error_value(value), do: value
end
