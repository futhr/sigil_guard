defmodule SigilGuard.Attestation.AgentPredicate do
  @moduledoc """
  Predicate extension validation for agent-to-agent trust statements.

  This module covers the `agent_request` and `agent_response` fields owned by
  SP.13 and the SP.01 action-digest preimage rows for those statement types.
  It deliberately stays below full attestation orchestration; card resolution,
  signing, and digest recomputation are handled by later integration layers.
  """

  alias SigilGuard.Canonical.JCS

  @sha256_regex ~r/^[0-9a-f]{64}$/
  @trust_levels ~w(low medium high)
  @response_statuses ~w(ok error)

  @type statement_type :: :agent_request | :agent_response
  @type error_reason :: :invalid_payload | :unsupported_number_range

  @doc """
  Build the SP.13 extension fields for an `agent_request` predicate.
  """
  @spec build_request(map(), keyword()) :: {:ok, map()} | {:error, :invalid_payload}
  def build_request(payload, opts \\ [])

  def build_request(payload, opts) when is_map(payload) and is_list(opts) do
    with {:ok, peer_agent_id} <- required_string(payload, "peer_agent"),
         {:ok, capability} <- required_string(payload, "capability"),
         {:ok, peer_agent} <- peer_agent(peer_agent_id, opts),
         {:ok, peer_trust} <- peer_trust(opts),
         :ok <- validate_unknown_peer_verdict(peer_agent, opts),
         {:ok, delegation_chain} <- request_delegation_chain(payload) do
      extension =
        %{
          "peer_agent" => peer_agent,
          "peer_trust" => peer_trust,
          "capability" => capability
        }
        |> maybe_put("delegation_chain", delegation_chain)

      {:ok, extension}
    end
  end

  def build_request(_, _), do: {:error, :invalid_payload}

  @doc """
  Build the SP.13 extension fields for an `agent_response` predicate.
  """
  @spec build_response(map(), keyword()) :: {:ok, map()} | {:error, :invalid_payload}
  def build_response(payload, opts \\ [])

  def build_response(payload, opts) when is_map(payload) and is_list(opts) do
    with {:ok, peer_agent_id} <- required_string(payload, "peer_agent"),
         {:ok, capability} <- required_string(payload, "capability"),
         {:ok, status} <- response_status(payload),
         {:ok, request_action_digest} <- request_action_digest(opts),
         {:ok, quarantined} <- quarantined(opts),
         {:ok, peer_agent} <- peer_agent(peer_agent_id, opts),
         {:ok, peer_trust} <- peer_trust(opts),
         :ok <- reject_present(payload, "delegation_chain") do
      {:ok,
       %{
         "peer_agent" => peer_agent,
         "peer_trust" => peer_trust,
         "capability" => capability,
         "request_action_digest" => request_action_digest,
         "status" => status,
         "quarantined" => quarantined
       }}
    end
  end

  def build_response(_, _), do: {:error, :invalid_payload}

  @doc """
  Validate SP.13 extension fields on a decoded predicate.
  """
  @spec validate(statement_type(), map()) :: :ok | {:error, :invalid_payload}
  def validate(:agent_request, predicate) when is_map(predicate) do
    with :ok <- reject_present(predicate, "tool"),
         {:ok, _} <- validate_peer_agent(field(predicate, "peer_agent"), predicate),
         {:ok, _} <- validate_peer_trust(field(predicate, "peer_trust")),
         {:ok, _} <- validate_non_empty_string(field(predicate, "capability")),
         {:ok, _} <- validate_optional_delegation_chain(predicate) do
      :ok
    else
      {:error, :invalid_payload} -> {:error, :invalid_payload}
    end
  end

  def validate(:agent_response, predicate) when is_map(predicate) do
    with :ok <- reject_present(predicate, "tool"),
         :ok <- reject_present(predicate, "delegation_chain"),
         {:ok, _} <- validate_peer_agent(field(predicate, "peer_agent"), predicate),
         {:ok, _} <- validate_peer_trust(field(predicate, "peer_trust")),
         {:ok, _} <- validate_non_empty_string(field(predicate, "capability")),
         {:ok, _} <- validate_sha256(field(predicate, "request_action_digest")),
         {:ok, _} <- validate_status(field(predicate, "status")),
         {:ok, _} <- validate_boolean(field(predicate, "quarantined")) do
      :ok
    else
      {:error, :invalid_payload} -> {:error, :invalid_payload}
    end
  end

  def validate(_, _), do: {:error, :invalid_payload}

  @doc """
  Return the SP.01 action-digest preimage for an A2A statement payload.
  """
  @spec action_preimage(statement_type(), map(), keyword()) ::
          {:ok, map()} | {:error, :invalid_payload}
  def action_preimage(statement_type, payload, opts \\ [])

  def action_preimage(:agent_request, payload, _) when is_map(payload) do
    with {:ok, peer_agent} <- required_string(payload, "peer_agent"),
         {:ok, capability} <- required_string(payload, "capability") do
      preimage =
        %{
          "statement_type" => "agent_request",
          "peer_agent" => peer_agent,
          "capability" => capability
        }
        |> maybe_put("arguments", optional_field(payload, "arguments"))

      {:ok, preimage}
    end
  end

  def action_preimage(:agent_response, payload, opts) when is_map(payload) and is_list(opts) do
    with {:ok, peer_agent} <- required_string(payload, "peer_agent"),
         {:ok, capability} <- required_string(payload, "capability"),
         {:ok, request_action_digest} <- request_action_digest(opts) do
      {:ok,
       %{
         "statement_type" => "agent_response",
         "peer_agent" => peer_agent,
         "capability" => capability,
         "request_action_digest" => request_action_digest
       }}
    end
  end

  def action_preimage(_, _, _), do: {:error, :invalid_payload}

  @doc """
  Compute the SP.01 action digest for an A2A statement payload.
  """
  @spec action_digest(statement_type(), map(), keyword()) ::
          {:ok, String.t()} | {:error, error_reason()}
  def action_digest(statement_type, payload, opts \\ []) do
    with {:ok, preimage} <- action_preimage(statement_type, payload, opts),
         {:ok, canonical} <- JCS.encode(preimage) do
      {:ok, sha256_hex(canonical)}
    else
      {:error, :invalid_map} -> {:error, :invalid_payload}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Hash the normalized payload delegation chain for order-preserving tamper tests.
  """
  @spec delegation_chain_digest(map()) ::
          {:ok, String.t()} | {:error, error_reason()}
  def delegation_chain_digest(payload) when is_map(payload) do
    with {:ok, chain} <- request_delegation_chain(payload),
         {:ok, canonical} <- JCS.encode(chain) do
      {:ok, sha256_hex(canonical)}
    else
      {:error, :invalid_map} -> {:error, :invalid_payload}
      {:error, reason} -> {:error, reason}
    end
  end

  def delegation_chain_digest(_), do: {:error, :invalid_payload}

  defp request_delegation_chain(payload) do
    case fetch_field(payload, "delegation_chain") do
      {:ok, chain} -> validate_delegation_chain(chain)
      :error -> {:ok, nil}
    end
  end

  defp validate_optional_delegation_chain(predicate) do
    case fetch_field(predicate, "delegation_chain") do
      {:ok, chain} -> validate_delegation_chain(chain)
      :error -> {:ok, nil}
    end
  end

  defp validate_delegation_chain(chain) when is_list(chain) and chain != [] do
    result =
      Enum.reduce_while(chain, {:ok, []}, fn hop, {:ok, hops} ->
        case validate_delegation_hop(hop) do
          {:ok, normalized} -> {:cont, {:ok, [normalized | hops]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)

    case result do
      {:ok, hops} -> {:ok, Enum.reverse(hops)}
      {:error, reason} -> {:error, reason}
    end
  end

  defp validate_delegation_chain(_), do: {:error, :invalid_payload}

  defp validate_delegation_hop(hop) when is_map(hop) do
    keys = normalized_keys(hop)

    with true <- keys in [["actor"], ["actor", "evidence"]],
         {:ok, actor} <- validate_non_empty_string(field(hop, "actor")),
         {:ok, evidence} <- optional_evidence(hop) do
      {:ok, maybe_put(%{"actor" => actor}, "evidence", evidence)}
    else
      _ -> {:error, :invalid_payload}
    end
  end

  defp validate_delegation_hop(_), do: {:error, :invalid_payload}

  defp optional_evidence(hop) do
    case fetch_field(hop, "evidence") do
      {:ok, value} -> validate_non_empty_string(value)
      :error -> {:ok, nil}
    end
  end

  defp peer_agent(peer_agent_id, opts) do
    peer_agent = %{"id" => peer_agent_id}

    case fetch_option(opts, :card_digest) do
      {:ok, digest} ->
        with {:ok, digest} <- validate_sha256(digest) do
          {:ok, Map.put(peer_agent, "card_digest", digest)}
        end

      :error ->
        {:ok, peer_agent}
    end
  end

  defp validate_peer_agent(%{} = peer_agent, predicate) do
    with {:ok, id} <- validate_non_empty_string(field(peer_agent, "id")),
         {:ok, card_digest} <- optional_card_digest(peer_agent),
         :ok <-
           validate_unknown_peer_verdict(
             %{"id" => id} |> maybe_put("card_digest", card_digest),
             predicate
           ) do
      {:ok, maybe_put(%{"id" => id}, "card_digest", card_digest)}
    end
  end

  defp validate_peer_agent(_, _), do: {:error, :invalid_payload}

  defp optional_card_digest(peer_agent) do
    case fetch_field(peer_agent, "card_digest") do
      {:ok, digest} -> validate_sha256(digest)
      :error -> {:ok, nil}
    end
  end

  defp validate_unknown_peer_verdict(%{"card_digest" => _}, _), do: :ok

  defp validate_unknown_peer_verdict(_, source) do
    case verdict(source) do
      "block" -> :ok
      "quarantine" -> :ok
      _ -> {:error, :invalid_payload}
    end
  end

  defp peer_trust(opts) do
    case fetch_option(opts, :peer_trust) do
      {:ok, trust} -> validate_peer_trust(normalize_atom_value(trust))
      :error -> {:error, :invalid_payload}
    end
  end

  defp validate_peer_trust(value) when value in @trust_levels, do: {:ok, value}
  defp validate_peer_trust(_), do: {:error, :invalid_payload}

  defp response_status(payload) do
    case required_string(payload, "status") do
      {:ok, status} -> validate_status(status)
      {:error, reason} -> {:error, reason}
    end
  end

  defp validate_status(value) when value in @response_statuses, do: {:ok, value}
  defp validate_status(_), do: {:error, :invalid_payload}

  defp request_action_digest(opts) do
    case fetch_option(opts, :request_action_digest) do
      {:ok, digest} -> validate_sha256(digest)
      :error -> {:error, :invalid_payload}
    end
  end

  defp quarantined(opts) do
    case fetch_option(opts, :quarantined) do
      {:ok, value} -> validate_boolean(value)
      :error -> {:error, :invalid_payload}
    end
  end

  defp required_string(map, key) do
    case fetch_field(map, key) do
      {:ok, value} -> validate_non_empty_string(value)
      :error -> {:error, :invalid_payload}
    end
  end

  defp validate_non_empty_string(value) when is_binary(value) and value != "", do: {:ok, value}
  defp validate_non_empty_string(_), do: {:error, :invalid_payload}

  defp validate_sha256(value) when is_binary(value) do
    if Regex.match?(@sha256_regex, value) do
      {:ok, value}
    else
      {:error, :invalid_payload}
    end
  end

  defp validate_sha256(_), do: {:error, :invalid_payload}

  defp validate_boolean(value) when is_boolean(value), do: {:ok, value}
  defp validate_boolean(_), do: {:error, :invalid_payload}

  defp reject_present(map, key) do
    case fetch_field(map, key) do
      {:ok, _} -> {:error, :invalid_payload}
      :error -> :ok
    end
  end

  defp optional_field(map, key) do
    case fetch_field(map, key) do
      {:ok, nil} -> nil
      {:ok, value} -> value
      :error -> nil
    end
  end

  defp field(map, key) do
    case fetch_field(map, key) do
      {:ok, value} -> value
      :error -> nil
    end
  end

  defp fetch_field(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} -> {:ok, value}
      :error -> fetch_atom_field(map, key)
    end
  end

  defp fetch_atom_field(map, key) do
    case Map.fetch(map, atom_key(key)) do
      {:ok, value} -> {:ok, value}
      :error -> :error
    end
  end

  defp fetch_option(opts, key) do
    case Keyword.fetch(opts, key) do
      {:ok, value} -> {:ok, value}
      :error -> :error
    end
  end

  defp verdict(opts) when is_list(opts), do: normalize_atom_value(Keyword.get(opts, :verdict))
  defp verdict(map) when is_map(map), do: normalize_atom_value(field(map, "verdict"))

  defp normalize_atom_value(value) when is_atom(value) and value not in [true, false, nil] do
    Atom.to_string(value)
  end

  defp normalize_atom_value(value), do: value

  defp normalized_keys(map) do
    map
    |> Map.keys()
    |> Enum.map(&normalize_key/1)
    |> Enum.sort()
  end

  defp normalize_key(key) when is_atom(key), do: Atom.to_string(key)
  defp normalize_key(key) when is_binary(key), do: key
  defp normalize_key(_), do: :invalid

  defp maybe_put(map, _, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp sha256_hex(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

  defp atom_key("arguments"), do: :arguments
  defp atom_key("actor"), do: :actor
  defp atom_key("card_digest"), do: :card_digest
  defp atom_key("capability"), do: :capability
  defp atom_key("delegation_chain"), do: :delegation_chain
  defp atom_key("evidence"), do: :evidence
  defp atom_key("id"), do: :id
  defp atom_key("peer_agent"), do: :peer_agent
  defp atom_key("peer_trust"), do: :peer_trust
  defp atom_key("quarantined"), do: :quarantined
  defp atom_key("request_action_digest"), do: :request_action_digest
  defp atom_key("status"), do: :status
  defp atom_key("tool"), do: :tool
  defp atom_key("verdict"), do: :verdict
end
