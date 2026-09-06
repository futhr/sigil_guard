defmodule SigilGuard.Policy do
  @moduledoc """
  Risk classification and trust-gated policy enforcement for SigilGuard.

  Maps actions to risk levels and evaluates whether a given trust level is
  sufficient to proceed. Supports configurable risk mappings, confirmation
  flow for borderline cases, and rate limiting.

  ## Risk Level Hierarchy

      :low < :medium < :high

  - **low** — Read-only, within workspace. Requires `:low` trust.
  - **medium** — State-modifying but recoverable. Requires `:medium` trust.
  - **high** — Destructive or irreversible. Requires `:high` trust.

  ## Default Trust Thresholds

  | Risk Level | Minimum Trust Required |
  |------------|----------------------|
  | `:low`     | `:low`               |
  | `:medium`  | `:medium`            |
  | `:high`    | `:high`              |

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

  @type risk_level :: :low | :medium | :high
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
    low: :low,
    medium: :medium,
    high: :high
  }

  @default_rate_table :sigil_guard_rates
  @rate_count {__MODULE__, :entries}
  @rate_prune {__MODULE__, :last_prune}

  @risk_order %{
    low: 0,
    medium: 1,
    high: 2
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

      iex> SigilGuard.Policy.evaluate("read_file", :medium)
      :allowed

      iex> SigilGuard.Policy.evaluate("delete_database", :low)
      :blocked

  """
  @spec evaluate(String.t(), Identity.trust_level(), keyword()) :: verdict()
  def evaluate(action, trust_level, opts \\ []) do
    with :ok <- validate_options(opts),
         {:ok, risk} <- effective_risk(action, opts),
         {:ok, required_trust} <- required_trust(risk, opts),
         :ok <- validate_trust_level(trust_level) do
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
    else
      {:error, reason} ->
        emit_decision(action, :invalid, trust_level, nil, reason)
        :blocked
    end
  end

  @doc """
  Classify the risk level of an action based on pattern matching.

  Uses `:risk_mappings` option or falls back to built-in heuristics based on
  action name prefixes.

  ## Built-in Risk Heuristics

    * `"delete_"`, `"drop_"`, `"destroy_"`, `"execute_"`, `"run_"` → `:high`
    * `"write_"`, `"update_"`, `"create_"`, `"modify_"`, `"send_"` → `:medium`
    * `"read_"`, `"get_"`, `"list_"`, `"search_"` → `:low`
    * Everything else → `:medium`

  """
  @spec classify_risk(String.t(), keyword()) :: risk_level()
  def classify_risk(action, opts \\ []) do
    mappings =
      if Keyword.keyword?(opts), do: Keyword.get(opts, :risk_mappings, %{}), else: :invalid

    case mapped_risk(action, mappings) do
      {:ok, nil} -> classify_by_prefix(action)
      {:ok, level} -> normalize_risk_level(level)
      {:error, _} -> :high
    end
  end

  defp validate_options(opts) do
    if Keyword.keyword?(opts), do: :ok, else: {:error, :invalid_options}
  end

  @doc """
  Perform a rate check for an identity performing an action.

  Returns `:ok` if within limits, or `{:error, :rate_limited}` if exceeded.

  This is a fixed-window counter: an identity's first request opens a
  window, requests within `:window_ms` count against `:max_requests`, and
  the next request after expiry opens a fresh one. Atomic ETS transitions enforce
  the per-window quota under contention. Up to `2 × max_requests` can pass in a
  burst straddling a window boundary, as with any fixed-window scheme.

  Stores hold at most 100,000 identities. Expired entries are reclaimed on use
  and through amortized sweeps; capacity exhaustion fails with `:rate_limited`.
  This is a per-node, per-boot limiter, not a distributed quota.

  ## Options

    * `:max_requests` — maximum requests per window (default: 100)
    * `:window_ms` — time window in milliseconds (default: 60_000)
    * `:rate_store` — ETS table name for rate tracking (default: `:sigil_guard_rates`)

  The default table is created and owned by `SigilGuard.Runtime`. A custom
  `:rate_store` table is created on first use
  and owned by the first calling process — its rate state is lost if that
  process exits.
  """
  @spec rate_check(String.t(), keyword()) :: :ok | {:error, :rate_limited}
  def rate_check(identity, opts \\ []) do
    with true <- is_binary(identity) and byte_size(identity) <= 4096,
         :ok <- validate_options(opts),
         {:ok, max_requests} <- positive_integer_option(opts, :max_requests, 100),
         {:ok, window_ms} <- positive_integer_option(opts, :window_ms, 60_000),
         {:ok, table} <- rate_store_option(opts) do
      checked_rate(identity, table, max_requests, window_ms)
    else
      _ -> {:error, :rate_limited}
    end
  end

  @doc """
  Ensure the ETS table used by `rate_check/2` exists.

  `SigilGuard.Runtime` creates the default table; call this only to pre-create
  a custom `:rate_store` table from a process that outlives the callers (the
  table is owned by the process that creates it).

  Safe to call concurrently — creation races resolve to the existing table.
  """
  @spec ensure_rate_table(atom()) :: :ok
  def ensure_rate_table(table \\ @default_rate_table) do
    case :ets.whereis(table) do
      :undefined ->
        try do
          :ets.new(table, [:named_table, :public, :set])
          :ok
        rescue
          # Lost a creation race with another process — table exists now.
          ArgumentError -> :ok
        end

      _ ->
        :ok
    end
  end

  @doc """
  Return the default trust threshold for a risk level.

  ## Examples

      iex> SigilGuard.Policy.trust_threshold(:high)
      :high

      iex> SigilGuard.Policy.trust_threshold(:low)
      :low

  """
  @spec trust_threshold(risk_level()) :: Identity.trust_level()
  def trust_threshold(risk_level) do
    Map.fetch!(@default_trust_thresholds, risk_level)
  end

  @doc """
  Return all risk levels in ascending order.

  ## Examples

      iex> SigilGuard.Policy.risk_levels()
      [:low, :medium, :high]

  """
  @spec risk_levels() :: [risk_level(), ...]
  def risk_levels do
    [:low, :medium, :high]
  end

  @doc """
  Compare two risk levels.

  ## Examples

      iex> SigilGuard.Policy.compare_risk(:low, :high)
      :lt

      iex> SigilGuard.Policy.compare_risk(:high, :medium)
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

  @prefix_risk_mappings [
    {"delete_", :high},
    {"drop_", :high},
    {"destroy_", :high},
    {"execute_", :high},
    {"run_", :high},
    {"write_", :medium},
    {"update_", :medium},
    {"create_", :medium},
    {"modify_", :medium},
    {"send_", :medium},
    {"read_", :low},
    {"get_", :low},
    {"list_", :low},
    {"search_", :low}
  ]

  defp effective_risk(action, opts) do
    case Keyword.fetch(opts, :risk_level) do
      {:ok, risk} ->
        validate_risk_level(risk)

      :error ->
        with {:ok, risk} <- classified_risk(action, opts) do
          validate_risk_level(risk)
        end
    end
  end

  defp classified_risk(action, opts) do
    mappings = Keyword.get(opts, :risk_mappings, %{})

    case mapped_risk(action, mappings) do
      {:ok, nil} -> {:ok, classify_by_prefix(action)}
      {:ok, level} -> {:ok, level}
      {:error, reason} -> {:error, reason}
    end
  end

  defp mapped_risk(action, mappings) when is_map(mappings) do
    {:ok, Map.get(mappings, action)}
  end

  defp mapped_risk(_, _), do: {:error, :invalid_risk_mappings}

  defp classify_by_prefix(action) when is_binary(action) do
    Enum.find_value(@prefix_risk_mappings, :medium, fn {prefix, level} ->
      if String.starts_with?(action, prefix), do: level
    end)
  end

  defp classify_by_prefix(_), do: :high

  defp normalize_risk_level(level) when level in [:low, :medium, :high], do: level
  defp normalize_risk_level(_), do: :high

  defp required_trust(risk, opts) do
    thresholds = Keyword.get(opts, :trust_thresholds, @default_trust_thresholds)

    with {:ok, thresholds} <- normalize_trust_thresholds(thresholds) do
      trust = Map.fetch!(thresholds, risk)
      {:ok, trust}
    end
  end

  defp normalize_trust_thresholds(thresholds) when is_map(thresholds) do
    merged = Map.merge(@default_trust_thresholds, Map.take(thresholds, risk_levels()))

    case Enum.find(merged, fn {_, trust} -> trust not in Identity.trust_levels() end) do
      nil -> {:ok, merged}
      _ -> {:error, :invalid_trust_thresholds}
    end
  end

  defp normalize_trust_thresholds(_), do: {:error, :invalid_trust_thresholds}

  defp validate_risk_level(level) when level in [:low, :medium, :high], do: {:ok, level}
  defp validate_risk_level(_), do: {:error, :invalid_risk_level}

  defp validate_trust_level(level) when level in [:low, :medium, :high], do: :ok
  defp validate_trust_level(_), do: {:error, :invalid_trust_level}

  defp one_level_below?(actual, required) do
    trust_levels = Identity.trust_levels()
    actual_idx = Enum.find_index(trust_levels, &(&1 == actual))
    required_idx = Enum.find_index(trust_levels, &(&1 == required))

    actual_idx != nil and required_idx != nil and required_idx - actual_idx == 1
  end

  defp checked_rate(identity, table, max_requests, window_ms) do
    identity = :crypto.hash(:sha256, identity)
    now = System.monotonic_time(:millisecond)

    ensure_rate_table(table)

    :ets.insert_new(table, {@rate_count, 0})
    prune_rates(table, now)
    claim_rate(identity, table, max_requests, now, now + window_ms)
  end

  defp prune_rates(table, now) do
    previous = :ets.lookup(table, @rate_prune)

    case previous do
      [{_, last}] when now - last < 60_000 ->
        :ok

      _ ->
        :ets.insert(table, {@rate_prune, now})

        removed =
          :ets.select_delete(table, [{{:"$1", :"$2", :"$3"}, [{:"=<", :"$3", now}], [true]}])

        :ets.update_counter(table, @rate_count, {2, -removed})
    end
  end

  defp claim_rate(identity, table, max_requests, now, expiry) do
    case :ets.lookup(table, identity) do
      [{^identity, count, current_expiry}] when current_expiry <= now ->
        removed = :ets.select_delete(table, [{{identity, count, current_expiry}, [], [true]}])
        :ets.update_counter(table, @rate_count, {2, -removed})
        claim_rate(identity, table, max_requests, now, expiry)

      [{^identity, count, _}] when count >= max_requests ->
        {:error, :rate_limited}

      [{^identity, count, current_expiry}] ->
        match = [
          {{identity, count, current_expiry}, [], [{{identity, count + 1, current_expiry}}]}
        ]

        if :ets.select_replace(table, match) == 1,
          do: :ok,
          else: claim_rate(identity, table, max_requests, now, expiry)

      [] ->
        insert_rate(identity, table, max_requests, now, expiry)
    end
  end

  defp insert_rate(identity, table, max_requests, now, expiry) do
    if :ets.update_counter(table, @rate_count, {2, 1}) > 100_000 do
      :ets.update_counter(table, @rate_count, {2, -1})
      {:error, :rate_limited}
    else
      if :ets.insert_new(table, {identity, 1, expiry}) do
        :ok
      else
        :ets.update_counter(table, @rate_count, {2, -1})
        claim_rate(identity, table, max_requests, now, expiry)
      end
    end
  end

  defp positive_integer_option(opts, key, default) do
    case Keyword.get(opts, key, default) do
      value when is_integer(value) and value > 0 -> {:ok, value}
      _ -> {:error, {:invalid_option, key}}
    end
  end

  defp rate_store_option(opts) do
    case Keyword.get(opts, :rate_store, @default_rate_table) do
      table when is_atom(table) -> {:ok, table}
      _ -> {:error, {:invalid_option, :rate_store}}
    end
  end

  defp emit_decision(action, risk, trust_level, required_trust, error_reason \\ nil) do
    SigilGuard.Telemetry.emit(
      [:sigil_guard, :policy, :decision],
      %{system_time: System.system_time()},
      %{
        action: action,
        risk_level: risk,
        trust_level: trust_level,
        trust_required: required_trust,
        error_reason: error_reason
      }
    )
  end
end
