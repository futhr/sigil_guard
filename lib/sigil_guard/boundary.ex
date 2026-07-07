defmodule SigilGuard.Boundary do
  @moduledoc """
  Normalized policy decision input for the boundary kernel (SP.04).

  A `%SigilGuard.Boundary{}` gathers everything `SigilGuard.BoundaryPolicy`
  needs to reach a deterministic verdict: the lifecycle phase, the source and
  sink boundaries, scanner hits and indicators, the SP.01 digests, actor and
  tool facts, and the sandbox identity. `new/1` normalizes a struct, map, or
  keyword list; `validate/1` rejects out-of-enum values with typed errors.

  `source_sensitivity` is an evaluation fact only - it is never part of the
  SP.01 context digest. `sandbox_id` and `isolation_level` (from `sandbox`) are
  digest-bound through `SigilGuard.Context`.
  """

  alias SigilGuard.Lifecycle

  @sha256_regex ~r/^[0-9a-f]{64}$/
  @source_sensitivities [:public, :internal, :private]
  @isolation_levels [:none, :container, :vm, :remote_attested]
  @trust_levels [:low, :medium, :high]

  @source_sensitivity_strings Map.new(@source_sensitivities, &{Atom.to_string(&1), &1})
  @isolation_level_strings Map.new(@isolation_levels, &{Atom.to_string(&1), &1})
  @trust_level_strings Map.new(@trust_levels, &{Atom.to_string(&1), &1})

  @list_fields [:hits, :indicators, :hook_results, :repo_changes]
  @digest_fields [:action_digest, :payload_digest, :context_digest]

  @type isolation_level :: :none | :container | :vm | :remote_attested
  @type source_sensitivity :: :public | :internal | :private

  @type error ::
          :invalid_boundary
          | :invalid_phase
          | :invalid_source
          | :invalid_sink
          | :invalid_source_sensitivity
          | :invalid_trust_level
          | :invalid_isolation_level

  @type t :: %__MODULE__{
          phase: Lifecycle.phase() | nil,
          source: atom() | String.t() | nil,
          sink: atom() | String.t() | nil,
          source_sensitivity: source_sensitivity(),
          actor: map() | nil,
          tool: map() | nil,
          resource: map() | nil,
          action_digest: String.t() | nil,
          payload_digest: String.t() | nil,
          context_digest: String.t() | nil,
          policy_file_digest: String.t() | nil,
          hits: list(),
          indicators: list(),
          hook_results: list(),
          repo_changes: list(),
          trust_level: SigilGuard.Identity.trust_level(),
          trust_zone: atom() | String.t() | nil,
          sandbox: map() | nil
        }

  defstruct phase: nil,
            source: nil,
            sink: nil,
            source_sensitivity: :internal,
            actor: nil,
            tool: nil,
            resource: nil,
            action_digest: nil,
            payload_digest: nil,
            context_digest: nil,
            policy_file_digest: nil,
            hits: [],
            indicators: [],
            hook_results: [],
            repo_changes: [],
            trust_level: :low,
            trust_zone: nil,
            sandbox: nil

  @known_keys ~w(
    phase source sink source_sensitivity actor tool resource action_digest
    payload_digest context_digest policy_file_digest hits indicators
    hook_results repo_changes trust_level trust_zone sandbox
  )

  @doc """
  Normalize a struct, map, or keyword list into `%SigilGuard.Boundary{}`.

  String enum values are mapped to their atoms; unknown values are left intact
  so `validate/1` can reject them. Does not validate.
  """
  @spec new(t() | map() | keyword()) :: t()
  def new(%__MODULE__{} = boundary), do: normalize_values(boundary)

  def new(fields) when is_list(fields), do: new(Map.new(fields))

  def new(fields) when is_map(fields) do
    fields
    |> atomize_known_keys()
    |> then(&struct(__MODULE__, &1))
    |> normalize_values()
  end

  @doc """
  Validate a normalized boundary, rejecting out-of-enum and malformed values.
  """
  @spec validate(t()) :: :ok | {:error, error()}
  def validate(%__MODULE__{} = boundary) do
    with :ok <- require_phase(boundary.phase),
         :ok <- require_present(boundary.source, :invalid_source),
         :ok <- require_present(boundary.sink, :invalid_sink),
         :ok <-
           require_member(
             boundary.source_sensitivity,
             @source_sensitivities,
             :invalid_source_sensitivity
           ),
         :ok <- require_member(boundary.trust_level, @trust_levels, :invalid_trust_level),
         :ok <- require_digests(boundary),
         :ok <- require_lists(boundary) do
      require_isolation(boundary.sandbox)
    end
  end

  def validate(_), do: {:error, :invalid_boundary}

  defp require_phase(phase) do
    if Lifecycle.phase?(phase), do: :ok, else: {:error, :invalid_phase}
  end

  defp require_present(value, _) when is_atom(value) and not is_nil(value), do: :ok
  defp require_present(value, _) when is_binary(value) and value != "", do: :ok
  defp require_present(_, reason), do: {:error, reason}

  defp require_member(value, allowed, reason) do
    if value in allowed, do: :ok, else: {:error, reason}
  end

  defp require_digests(boundary) do
    Enum.reduce_while(@digest_fields, :ok, fn field, :ok ->
      case valid_digest(Map.fetch!(boundary, field)) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp valid_digest(value) when is_binary(value) do
    if Regex.match?(@sha256_regex, value), do: :ok, else: {:error, :invalid_boundary}
  end

  defp valid_digest(_), do: {:error, :invalid_boundary}

  defp require_lists(boundary) do
    if Enum.all?(@list_fields, &is_list(Map.fetch!(boundary, &1))) do
      :ok
    else
      {:error, :invalid_boundary}
    end
  end

  defp require_isolation(nil), do: :ok

  defp require_isolation(sandbox) when is_map(sandbox) do
    case fetch_field(sandbox, "isolation_level") do
      {:ok, nil} -> :ok
      {:ok, level} -> require_member(level, @isolation_levels, :invalid_isolation_level)
      :error -> :ok
    end
  end

  defp require_isolation(_), do: {:error, :invalid_boundary}

  defp normalize_values(%__MODULE__{} = boundary) do
    %{
      boundary
      | phase: normalize_phase(boundary.phase),
        source_sensitivity:
          normalize_enum(boundary.source_sensitivity, @source_sensitivity_strings),
        trust_level: normalize_enum(boundary.trust_level, @trust_level_strings),
        sandbox: normalize_sandbox(boundary.sandbox)
    }
  end

  defp normalize_phase(phase) do
    case Lifecycle.cast(phase) do
      {:ok, phase} -> phase
      :error -> phase
    end
  end

  defp normalize_sandbox(sandbox) when is_map(sandbox) do
    case fetch_field(sandbox, "isolation_level") do
      {:ok, level} ->
        put_field(sandbox, "isolation_level", normalize_enum(level, @isolation_level_strings))

      :error ->
        sandbox
    end
  end

  defp normalize_sandbox(sandbox), do: sandbox

  defp normalize_enum(value, strings) when is_binary(value) do
    Map.get(strings, value, value)
  end

  defp normalize_enum(value, _), do: value

  defp atomize_known_keys(fields) do
    Map.new(fields, fn {key, value} -> {atomize_key(key), value} end)
  end

  defp atomize_key(key) when is_atom(key), do: key

  defp atomize_key(key) when is_binary(key) do
    if key in @known_keys, do: String.to_existing_atom(key), else: key
  end

  defp fetch_field(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} -> {:ok, value}
      :error -> Map.fetch(map, isolation_atom(key))
    end
  end

  defp put_field(map, key, value) do
    if Map.has_key?(map, key),
      do: Map.put(map, key, value),
      else: Map.put(map, isolation_atom(key), value)
  end

  defp isolation_atom("isolation_level"), do: :isolation_level
end
