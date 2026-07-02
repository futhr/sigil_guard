defmodule SigilGuard.TrustProfile do
  @moduledoc """
  SigilGuard agent-trust profile registry and Statement validator.

  The registry is closed over the SP.01 statement types. Validation accepts a
  decoded in-toto Statement, normalizes its Statement envelope shape through
  `SigilGuard.Attestation.Statement`, and then checks SigilGuard profile and
  statement-type constraints without deriving atoms from external strings.
  """

  alias SigilGuard.Attestation.Statement

  @profile_id "sigil_guard_agent_trust/v1"
  @profile_stem "sigil_guard_agent_trust/"

  @statement_types [
    :tool_request,
    :tool_result,
    :model_ingress,
    :model_egress,
    :repo_change,
    :release,
    :agent_request,
    :agent_response
  ]

  @registry Enum.map(@statement_types, fn type ->
              type_string = Atom.to_string(type)
              {type, "https://sigilguard.dev/attestation/#{type_string}/v1", type_string}
            end)

  @type statement_type ::
          :tool_request
          | :tool_result
          | :model_ingress
          | :model_egress
          | :repo_change
          | :release
          | :agent_request
          | :agent_response

  @type validate_error ::
          :invalid_profile
          | :unsupported_profile_version
          | :unknown_statement_type
          | :invalid_payload

  @doc """
  Return the SP.01 SigilGuard agent-trust profile id.
  """
  @spec profile_id() :: String.t()
  def profile_id, do: @profile_id

  @doc """
  Return registered statement types in fixed dispatch order.
  """
  @spec statement_types() :: [statement_type(), ...]
  def statement_types, do: @statement_types

  @doc """
  Return the predicate type URI for a registered statement type.
  """
  @spec predicate_type(statement_type()) ::
          {:ok, String.t()} | {:error, :unknown_statement_type}
  def predicate_type(statement_type) do
    case List.keyfind(@registry, statement_type, 0) do
      {^statement_type, uri, _} -> {:ok, uri}
      nil -> {:error, :unknown_statement_type}
    end
  end

  @doc """
  Validate and normalize a decoded SigilGuard agent-trust Statement.
  """
  @spec validate(map()) :: {:ok, map()} | {:error, validate_error()}
  def validate(statement) do
    with {:ok, statement} <- Statement.parse(statement),
         {:ok, _, type_string} <- registry_entry(statement["predicateType"]),
         :ok <- validate_profile(statement["predicate"]["profile"]),
         :ok <- validate_statement_type_field(statement["predicate"], type_string) do
      {:ok, statement}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp registry_entry(predicate_type) when is_binary(predicate_type) do
    case Enum.find(@registry, fn {_, uri, _} -> uri == predicate_type end) do
      {statement_type, ^predicate_type, type_string} -> {:ok, statement_type, type_string}
      nil -> {:error, :unknown_statement_type}
    end
  end

  defp registry_entry(_), do: {:error, :unknown_statement_type}

  defp validate_profile(@profile_id), do: :ok

  defp validate_profile(profile) when is_binary(profile) do
    if String.starts_with?(profile, @profile_stem) do
      {:error, :unsupported_profile_version}
    else
      {:error, :invalid_profile}
    end
  end

  defp validate_profile(_), do: {:error, :invalid_profile}

  defp validate_statement_type_field(predicate, expected_type) do
    case Map.fetch(predicate, "statement_type") do
      {:ok, ^expected_type} -> :ok
      {:ok, type} when is_binary(type) -> {:error, :unknown_statement_type}
      {:ok, _} -> {:error, :invalid_payload}
      :error -> {:error, :invalid_payload}
    end
  end
end
