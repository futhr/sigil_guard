defmodule SigilGuard.Context do
  @moduledoc """
  Boundary metadata for SigilGuard runtime decisions.

  A context labels where content came from, where it is going, who is
  acting, and which trust boundary is being crossed. Regex scanner hits
  are only one signal; phase-2 runtime gates use this metadata to decide
  whether a hit should be allowed, redacted, quarantined, confirmed, or
  blocked.
  """

  @type phase ::
          :inbound_user
          | :tool_request
          | :tool_result
          | :outbound_model
          | :repo_change

  @type trust_zone :: :trusted | :semi_trusted | :untrusted
  @type sink :: :internal | :model | :user | :tool | :external | :network | :log | :repo
  @type origin :: :unknown | :user | :model | :tool | :resource | :repo | :registry | atom()

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
            metadata: %{}

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
    struct(__MODULE__, atom_context)
  end

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
end
