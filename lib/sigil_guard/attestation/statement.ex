defmodule SigilGuard.Attestation.Statement do
  @moduledoc """
  in-toto Statement builder and parser for SigilGuard attestations.

  This module owns the Statement envelope payload shape and subject ordering
  rules. It does not validate the SigilGuard statement-type registry; that is
  owned by `SigilGuard.TrustProfile`.
  """

  @statement_type "https://in-toto.io/Statement/v1"
  @required_subjects ~w(action payload context)
  @manifest_subject "manifest"
  @subject_order ~w(action payload context manifest)
  @sha256_regex ~r/^[0-9a-f]{64}$/

  @type digest_name :: :action | :payload | :context | :manifest | String.t()
  @type digests :: %{required(digest_name()) => String.t()}
  @type statement :: %{required(String.t()) => String.t() | map() | [map()]}

  @doc """
  Return the in-toto Statement v1 type URI.
  """
  @spec statement_type() :: String.t()
  def statement_type, do: @statement_type

  @doc """
  Build a SigilGuard in-toto Statement from predicate fields and digests.
  """
  @spec build(predicate_type :: String.t(), predicate :: map(), digests :: digests()) ::
          {:ok, statement()} | {:error, :invalid_profile}
  def build(predicate_type, predicate, digests)
      when is_binary(predicate_type) and predicate_type != "" and is_map(predicate) and
             is_map(digests) do
    with {:ok, subject} <- build_subject(digests) do
      {:ok,
       %{
         "_type" => @statement_type,
         "predicate" => predicate,
         "predicateType" => predicate_type,
         "subject" => subject
       }}
    end
  end

  def build(_, _, _), do: {:error, :invalid_profile}

  @doc """
  Validate and normalize a decoded in-toto Statement map.
  """
  @spec parse(term()) :: {:ok, statement()} | {:error, :invalid_profile}
  def parse(%{} = statement) do
    with :ok <- require_statement_type(field(statement, "_type")),
         predicate_type when is_binary(predicate_type) <- field(statement, "predicateType"),
         predicate when is_map(predicate) <- field(statement, "predicate"),
         {:ok, subject} <- parse_subject(field(statement, "subject")) do
      {:ok,
       %{
         "_type" => @statement_type,
         "predicate" => predicate,
         "predicateType" => predicate_type,
         "subject" => subject
       }}
    else
      _ -> {:error, :invalid_profile}
    end
  end

  def parse(_), do: {:error, :invalid_profile}

  defp build_subject(digests) do
    names =
      if present_digest?(digests, @manifest_subject) do
        @subject_order
      else
        @required_subjects
      end

    result =
      Enum.reduce_while(names, {:ok, []}, fn name, {:ok, subjects} ->
        case fetch_digest(digests, name) do
          {:ok, digest} -> {:cont, {:ok, [subject_entry(name, digest) | subjects]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)

    case result do
      {:ok, subjects} -> {:ok, Enum.reverse(subjects)}
      {:error, reason} -> {:error, reason}
    end
  end

  defp present_digest?(digests, name) do
    case fetch_raw_digest(digests, name) do
      value when is_binary(value) -> value != ""
      _ -> false
    end
  end

  defp fetch_digest(digests, name) do
    case fetch_raw_digest(digests, name) do
      digest when is_binary(digest) ->
        validate_digest(digest)

      _ ->
        {:error, :invalid_profile}
    end
  end

  defp fetch_raw_digest(digests, name) do
    case Map.fetch(digests, name) do
      {:ok, value} -> value
      :error -> Map.get(digests, atom_key(name))
    end
  end

  defp subject_entry(name, digest) do
    %{"name" => name, "digest" => %{"sha256" => digest}}
  end

  defp parse_subject(subjects) when is_list(subjects) do
    with {:ok, parsed} <- parse_subject_entries(subjects),
         :ok <- validate_subject_order(parsed) do
      {:ok, Enum.map(parsed, fn {name, digest} -> subject_entry(name, digest) end)}
    end
  end

  defp parse_subject(_), do: {:error, :invalid_profile}

  defp parse_subject_entries(subjects) do
    result =
      Enum.reduce_while(subjects, {:ok, []}, fn subject, {:ok, parsed} ->
        case parse_subject_entry(subject) do
          {:ok, entry} -> {:cont, {:ok, [entry | parsed]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)

    case result do
      {:ok, parsed} -> {:ok, Enum.reverse(parsed)}
      {:error, reason} -> {:error, reason}
    end
  end

  defp parse_subject_entry(%{} = subject) do
    name = field(subject, "name")
    digest_map = field(subject, "digest")

    with true <- is_binary(name),
         true <- is_map(digest_map),
         digest when is_binary(digest) <- field(digest_map, "sha256"),
         {:ok, digest} <- validate_digest(digest) do
      {:ok, {name, digest}}
    else
      _ -> {:error, :invalid_profile}
    end
  end

  defp parse_subject_entry(_), do: {:error, :invalid_profile}

  defp validate_subject_order(parsed) do
    names = Enum.map(parsed, &elem(&1, 0))

    cond do
      names == @required_subjects -> :ok
      names == @subject_order -> :ok
      true -> {:error, :invalid_profile}
    end
  end

  defp validate_digest(digest) do
    if Regex.match?(@sha256_regex, digest) do
      {:ok, digest}
    else
      {:error, :invalid_profile}
    end
  end

  defp require_statement_type(@statement_type), do: :ok
  defp require_statement_type(_), do: {:error, :invalid_profile}

  defp field(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} -> value
      :error -> Map.get(map, atom_key(key))
    end
  end

  defp atom_key("_type"), do: :_type
  defp atom_key("action"), do: :action
  defp atom_key("context"), do: :context
  defp atom_key("digest"), do: :digest
  defp atom_key("manifest"), do: :manifest
  defp atom_key("name"), do: :name
  defp atom_key("payload"), do: :payload
  defp atom_key("predicate"), do: :predicate
  defp atom_key("predicateType"), do: :predicateType
  defp atom_key("sha256"), do: :sha256
  defp atom_key("subject"), do: :subject
end
