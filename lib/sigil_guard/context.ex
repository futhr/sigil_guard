defmodule SigilGuard.Context do
  @moduledoc """
  Describes the trust boundary crossed by a SigilGuard decision.

  A context records where content came from, where it is going, who is acting,
  which tool or resource is involved, and what isolation surrounds the action.
  `SigilGuard.Runtime.Gate` combines these labels with scanner, manifest,
  repository, and host-policy signals to allow, redact, quarantine, confirm,
  or block the boundary crossing.

  Values may be supplied as a struct, map, or keyword list. Known string keys
  are normalized without creating atoms from untrusted input. Invalid enum
  values fail closed through `validate/1`.

  MCP Apps calls should use `origin: :app`, identify the trusted
  `mcp_server`, and name the `resource_uri` where relevant. Ordinary
  model-initiated tool calls use `origin: :model`.

  ## Example

      iex> context =
      ...>   SigilGuard.Context.new(
      ...>     phase: :tool_request,
      ...>     origin: :app,
      ...>     sink: :tool,
      ...>     mcp_server: "https://mcp.example.com",
      ...>     resource_uri: "ui://repo/review"
      ...>   )
      ...>
      ...> SigilGuard.Context.validate(context)
      :ok
  """

  @type phase ::
          :inbound_user
          | :tool_request
          | :tool_result
          | :outbound_model
          | :repo_change

  @type trust_zone :: :trusted | :semi_trusted | :untrusted
  @type sink :: :internal | :model | :user | :tool | :external | :network | :log | :repo
  @type origin ::
          :unknown | :user | :model | :tool | :app | :resource | :repo | :registry | atom()
  @type isolation_level :: :none | :container | :vm | :remote_attested
  @type network_posture :: :none | :outbound | :bidirectional

  @type t :: %__MODULE__{
          phase: phase(),
          actor: String.t() | nil,
          identity: String.t() | nil,
          trust_level: SigilGuard.Identity.trust_level(),
          origin: origin(),
          source: String.t() | nil,
          sink: sink(),
          mcp_server: String.t() | nil,
          tool: String.t() | nil,
          resource_uri: String.t() | nil,
          action: String.t() | nil,
          trust_zone: trust_zone(),
          intended_audience: atom(),
          sandbox_id: String.t() | nil,
          isolation_level: isolation_level() | nil,
          workspace_root_digest: String.t() | nil,
          network_posture: network_posture() | nil,
          metadata: map()
        }

  @enforce_keys []
  defstruct phase: :tool_request,
            actor: nil,
            identity: nil,
            trust_level: :low,
            origin: :unknown,
            source: nil,
            sink: :internal,
            mcp_server: nil,
            tool: nil,
            resource_uri: nil,
            action: nil,
            trust_zone: :semi_trusted,
            intended_audience: :internal,
            sandbox_id: nil,
            isolation_level: nil,
            workspace_root_digest: nil,
            network_posture: nil,
            metadata: %{}

  @phases ~w(inbound_user tool_request tool_result outbound_model repo_change)a
  @sinks ~w(internal model user tool external network log repo)a
  @origins ~w(unknown user model tool app resource repo registry)a
  @trust_levels ~w(low medium high)a
  @trust_zones ~w(trusted semi_trusted untrusted)a
  @audiences ~w(internal model user tool external network log repo)a
  @isolation_levels ~w(none container vm remote_attested)a
  @network_postures ~w(none outbound bidirectional)a

  @doc """
  Normalize a context struct, map, or keyword list into `%SigilGuard.Context{}`.
  """
  @spec new(t() | map() | keyword()) :: t()
  def new(%__MODULE__{} = context), do: context

  def new(context) when is_list(context) do
    context
    |> Map.new()
    |> new()
  end

  def new(context) when is_map(context) do
    atom_context = atomize_known_keys(context)

    struct(__MODULE__, normalize_known_values(atom_context))
  end

  @doc """
  Normalize context input into an override map without applying defaults.

  Known string keys become their existing struct-field atoms. Unknown keys are
  retained as strings and no atoms are created from external input.
  """
  @spec overrides(t() | map() | keyword() | term()) :: map()
  def overrides(%__MODULE__{} = context), do: Map.from_struct(context)

  def overrides(context) when is_list(context) do
    if Keyword.keyword?(context) do
      context
      |> Map.new()
      |> overrides()
    else
      %{}
    end
  end

  def overrides(context) when is_map(context), do: atomize_known_keys(context)
  def overrides(_), do: %{}

  @doc """
  Validate normalized boundary context values.

  Runtime gates use this to fail closed on malformed boundary labels before
  policy, scanner, or telemetry code can make decisions from invalid values.
  """
  @spec validate(t() | map() | keyword()) :: :ok | {:error, atom()}
  def validate(%__MODULE__{} = context) do
    with :ok <- require_member(context.phase, @phases, :invalid_phase),
         :ok <- require_member(context.sink, @sinks, :invalid_sink),
         :ok <- require_origin(context.origin),
         :ok <- require_member(context.trust_level, @trust_levels, :invalid_trust_level),
         :ok <- require_member(context.trust_zone, @trust_zones, :invalid_trust_zone),
         :ok <- require_audience(context.intended_audience),
         :ok <- require_isolation_level(context.isolation_level),
         :ok <- require_network_posture(context.network_posture) do
      require_map(context.metadata, :invalid_metadata)
    end
  end

  def validate(context) when is_map(context) or is_list(context) do
    context
    |> new()
    |> validate()
  end

  def validate(_), do: {:error, :invalid_context}

  @doc """
  Return the action string used by policy evaluation.
  """
  @spec action_name(t(), term()) :: String.t()
  def action_name(%__MODULE__{} = context, payload) do
    case fetch_action_name(context, payload) do
      {:ok, action} -> action
      {:error, _} -> "tool_call"
    end
  end

  def action_name(_, payload), do: action_name(new(%{}), payload)

  @doc """
  Strictly fetch the action string used by runtime policy evaluation.

  Missing fields fall back through the known aliases. Present non-binary fields
  are treated as malformed instead of being hidden by later aliases.
  """
  @spec fetch_action_name(t(), term()) :: {:ok, String.t()} | {:error, :invalid_action}
  def fetch_action_name(%__MODULE__{} = context, payload) do
    with {:ok, nil} <- first_context_string(context, [:action, :tool], :invalid_action),
         {:ok, nil} <-
           first_string(
             payload,
             [:action, "action", :tool, "tool", :name, "name"],
             :invalid_action
           ) do
      {:ok, "tool_call"}
    else
      {:ok, action} when is_binary(action) -> {:ok, action}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Strictly extract scan text from common payload shapes.

  Missing fields return `{:ok, nil}`. Present non-binary text fields are treated
  as malformed instead of being hidden by later aliases.
  """
  @spec fetch_text(term()) :: {:ok, String.t() | nil} | {:error, :invalid_text}
  def fetch_text(payload) when is_binary(payload), do: {:ok, payload}

  def fetch_text(payload) when is_map(payload) do
    first_string(
      payload,
      [:text, "text", :content, "content", :output, "output", :body, "body"],
      :invalid_text
    )
  end

  def fetch_text(_), do: {:ok, nil}

  @doc """
  Extract scan text from common payload shapes.
  """
  @spec text(term()) :: String.t() | nil
  def text(payload) do
    case fetch_text(payload) do
      {:ok, text} -> text
      {:error, _} -> nil
    end
  end

  defp first_context_string(%__MODULE__{} = context, keys, error) do
    context
    |> Map.from_struct()
    |> first_string(keys, error)
  end

  defp first_string(map, keys, error) when is_map(map) do
    Enum.reduce_while(keys, {:ok, nil}, fn key, {:ok, nil} ->
      case Map.fetch(map, key) do
        {:ok, nil} -> {:cont, {:ok, nil}}
        {:ok, value} when is_binary(value) -> {:halt, {:ok, value}}
        {:ok, _} -> {:halt, {:error, error}}
        :error -> {:cont, {:ok, nil}}
      end
    end)
  end

  defp first_string(_, _, _), do: {:ok, nil}

  defp atomize_known_keys(context) do
    known =
      __MODULE__.__struct__()
      |> Map.keys()
      |> MapSet.new()

    Map.new(context, &atomize_known_key(&1, known))
  end

  defp atomize_known_key({key, value}, known) when is_binary(key) do
    case existing_atom(key) do
      {:ok, atom_key} -> {known_key(atom_key, key, known), value}
      :error -> {key, value}
    end
  end

  defp atomize_known_key(pair, _), do: pair

  defp known_key(atom_key, key, known) do
    if MapSet.member?(known, atom_key), do: atom_key, else: key
  end

  defp existing_atom(key) do
    {:ok, String.to_existing_atom(key)}
  rescue
    ArgumentError -> :error
  end

  defp normalize_known_values(context) do
    context
    |> normalize_known_value(:phase, @phases)
    |> normalize_known_value(:sink, @sinks)
    |> normalize_known_value(:origin, @origins)
    |> normalize_known_value(:trust_level, @trust_levels)
    |> normalize_known_value(:trust_zone, @trust_zones)
    |> normalize_known_value(:intended_audience, @audiences)
    |> normalize_known_value(:isolation_level, @isolation_levels)
    |> normalize_known_value(:network_posture, @network_postures)
  end

  defp normalize_known_value(context, key, allowed) do
    if Map.has_key?(context, key) do
      Map.update!(context, key, &normalize_enum_value(&1, allowed))
    else
      context
    end
  end

  defp normalize_enum_value(value, allowed) when is_binary(value) do
    Enum.find(allowed, value, &(Atom.to_string(&1) == value))
  end

  defp normalize_enum_value(value, _), do: value

  defp require_member(value, allowed, reason) do
    if value in allowed, do: :ok, else: {:error, reason}
  end

  defp require_origin(origin) when is_atom(origin), do: :ok
  defp require_origin(_), do: {:error, :invalid_origin}

  defp require_isolation_level(nil), do: :ok
  defp require_isolation_level(level) when level in @isolation_levels, do: :ok
  defp require_isolation_level(_), do: {:error, :invalid_isolation_level}

  defp require_network_posture(nil), do: :ok
  defp require_network_posture(posture) when posture in @network_postures, do: :ok
  defp require_network_posture(_), do: {:error, :invalid_network_posture}

  defp require_audience(audience) when is_atom(audience), do: :ok
  defp require_audience(_), do: {:error, :invalid_audience}

  defp require_map(value, _) when is_map(value), do: :ok
  defp require_map(_, reason), do: {:error, reason}
end
