defmodule SigilGuard.Policy do
  @moduledoc """
  Risk classification and trust-gated policy enforcement for the SIGIL protocol.

  Maps actions to risk levels and evaluates whether a given trust level is
  sufficient to proceed. Supports configurable risk mappings, confirmation
  flow for borderline cases, and rate limiting.

  ## Risk Levels

      :none < :low < :medium < :high < :critical

  ## Default Trust Thresholds

  | Risk Level | Minimum Trust Required |
  |------------|----------------------|
  | `:none`    | `:anonymous`         |
  | `:low`     | `:anonymous`         |
  | `:medium`  | `:authenticated`     |
  | `:high`    | `:verified`          |
  | `:critical`| `:sovereign`         |

  ## Custom Policy Implementation

      defmodule MyApp.StrictPolicy do
        @behaviour SigilGuard.Policy

        @impl true
        def evaluate(action, trust_level, opts) do
          # Custom logic
        end

        @impl true
        def classify_risk(action, opts) do
          # Custom risk classification
        end
      end

  """

  alias SigilGuard.Identity

  @type risk_level :: :none | :low | :medium | :high | :critical
  @type verdict :: :allowed | :blocked | {:confirm, String.t()}

  @doc "Evaluate an action against a trust level and return a verdict."
  @callback evaluate(
              action :: String.t(),
              trust_level :: Identity.trust_level(),
              opts :: keyword()
            ) ::
              verdict()

  @doc "Classify the risk level of an action."
  @callback classify_risk(action :: String.t(), opts :: keyword()) :: risk_level()

  @default_trust_thresholds %{
    none: :anonymous,
    low: :anonymous,
    medium: :authenticated,
    high: :verified,
    critical: :sovereign
  }

  @risk_order %{
    none: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
  }

  @doc """
  Evaluate an action against a trust level.

  Returns `:allowed` if trust is sufficient, `{:confirm, reason}` if the caller
  is one trust level below the threshold (allowing interactive confirmation),
  or `:blocked` otherwise.

  ## Options

    * `:risk_level` — override the risk classification (default: look up via `:risk_mappings`)
    * `:risk_mappings` — map of action pattern to risk level
    * `:trust_thresholds` — override default trust thresholds per risk level

  ## Examples

      iex> SigilGuard.Policy.evaluate("read_file", :authenticated)
      :allowed

      iex> SigilGuard.Policy.evaluate("delete_database", :anonymous)
      :blocked

  """
  @spec evaluate(String.t(), Identity.trust_level(), keyword()) :: verdict()
  def evaluate(action, trust_level, opts \\ []) do
    risk = Keyword.get_lazy(opts, :risk_level, fn -> classify_risk(action, opts) end)
    thresholds = Keyword.get(opts, :trust_thresholds, @default_trust_thresholds)
    required_trust = Map.get(thresholds, risk, :authenticated)

    emit_decision(action, risk, trust_level, required_trust)

    cond do
      Identity.sufficient_trust?(trust_level, required_trust) ->
        :allowed

      one_level_below?(trust_level, required_trust) ->
        {:confirm,
         "Action '#{action}' (risk: #{risk}) requires #{required_trust} trust, " <>
           "but caller has #{trust_level}. Manual confirmation allowed."}

      true ->
        :blocked
    end
  end

  @doc """
  Classify the risk level of an action based on pattern matching.

  Uses `:risk_mappings` option or falls back to built-in heuristics based on
  action name prefixes.

  ## Built-in Risk Heuristics

    * `"delete_"`, `"drop_"`, `"destroy_"` → `:critical`
    * `"write_"`, `"update_"`, `"execute_"`, `"run_"` → `:high`
    * `"create_"`, `"modify_"`, `"send_"` → `:medium`
    * `"read_"`, `"get_"`, `"list_"`, `"search_"` → `:low`
    * Everything else → `:medium`

  """
  @spec classify_risk(String.t(), keyword()) :: risk_level()
  def classify_risk(action, opts \\ []) do
    mappings = Keyword.get(opts, :risk_mappings, %{})

    case Map.get(mappings, action) do
      nil -> classify_by_prefix(action)
      level -> level
    end
  end

  @doc """
  Perform a rate check for an identity performing an action.

  Returns `:ok` if within limits, or `{:error, :rate_limited}` if exceeded.

  This is a simple token-bucket check. For production use, implement
  `SigilGuard.Policy` behaviour with a proper rate limiter backend.

  ## Options

    * `:max_requests` — maximum requests per window (default: 100)
    * `:window_ms` — time window in milliseconds (default: 60_000)
    * `:rate_store` — ETS table name for rate tracking (default: `:sigil_guard_rates`)

  """
  @spec rate_check(String.t(), keyword()) :: :ok | {:error, :rate_limited}
  def rate_check(identity, opts \\ []) do
    max_requests = Keyword.get(opts, :max_requests, 100)
    window_ms = Keyword.get(opts, :window_ms, 60_000)
    table = Keyword.get(opts, :rate_store, :sigil_guard_rates)

    now = System.monotonic_time(:millisecond)

    ensure_rate_table(table)

    case :ets.lookup(table, identity) do
      [{^identity, count, window_start}] when now - window_start < window_ms ->
        if count >= max_requests do
          {:error, :rate_limited}
        else
          :ets.update_counter(table, identity, {2, 1})
          :ok
        end

      _expired_or_new ->
        :ets.insert(table, {identity, 1, now})
        :ok
    end
  end

  @doc """
  Return the default trust threshold for a risk level.

  ## Examples

      iex> SigilGuard.Policy.trust_threshold(:high)
      :verified

      iex> SigilGuard.Policy.trust_threshold(:low)
      :anonymous

  """
  @spec trust_threshold(risk_level()) :: Identity.trust_level()
  def trust_threshold(risk_level) do
    Map.fetch!(@default_trust_thresholds, risk_level)
  end

  @doc """
  Return all risk levels in ascending order.

  ## Examples

      iex> SigilGuard.Policy.risk_levels()
      [:none, :low, :medium, :high, :critical]

  """
  @spec risk_levels() :: [risk_level(), ...]
  def risk_levels do
    [:none, :low, :medium, :high, :critical]
  end

  @doc """
  Compare two risk levels.

  ## Examples

      iex> SigilGuard.Policy.compare_risk(:low, :high)
      :lt

      iex> SigilGuard.Policy.compare_risk(:critical, :medium)
      :gt

  """
  @spec compare_risk(risk_level(), risk_level()) :: :lt | :eq | :gt
  def compare_risk(a, b) do
    ord_a = Map.fetch!(@risk_order, a)
    ord_b = Map.fetch!(@risk_order, b)

    cond do
      ord_a < ord_b -> :lt
      ord_a > ord_b -> :gt
      true -> :eq
    end
  end

  # -- Private --

  @prefix_risk_mappings [
    {"delete_", :critical},
    {"drop_", :critical},
    {"destroy_", :critical},
    {"write_", :high},
    {"update_", :high},
    {"execute_", :high},
    {"run_", :high},
    {"create_", :medium},
    {"modify_", :medium},
    {"send_", :medium},
    {"read_", :low},
    {"get_", :low},
    {"list_", :low},
    {"search_", :low}
  ]

  defp classify_by_prefix(action) do
    Enum.find_value(@prefix_risk_mappings, :medium, fn {prefix, level} ->
      if String.starts_with?(action, prefix), do: level
    end)
  end

  defp one_level_below?(actual, required) do
    trust_levels = Identity.trust_levels()
    actual_idx = Enum.find_index(trust_levels, &(&1 == actual))
    required_idx = Enum.find_index(trust_levels, &(&1 == required))

    actual_idx != nil and required_idx != nil and required_idx - actual_idx == 1
  end

  defp emit_decision(action, risk, trust_level, required_trust) do
    SigilGuard.Telemetry.emit(
      [:sigil_guard, :policy, :decision],
      %{system_time: System.system_time()},
      %{
        action: action,
        risk_level: risk,
        trust_level: trust_level,
        trust_required: required_trust
      }
    )
  end

  defp ensure_rate_table(table) do
    case :ets.whereis(table) do
      :undefined ->
        :ets.new(table, [:named_table, :public, :set])

      _ref ->
        :ok
    end
  end
end
