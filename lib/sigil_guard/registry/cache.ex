defmodule SigilGuard.Registry.Cache do
  @moduledoc """
  GenServer-based TTL cache for SIGIL registry data.

  Fetches pattern bundles on startup and refreshes them periodically based
  on the configured TTL. On fetch failure, retains the last known good
  bundle, tracks the data source for observability, and retries after
  `:registry_retry_ms` instead of waiting out the full TTL.

  ## Source Tracking

  The cache tracks where its current data came from:

    * `:registry` — freshly fetched from the SIGIL registry
    * `:fallback` — last fetch failed; serving built-in patterns (if no
      fetch ever succeeded) or the last known good bundle
    * `:empty` — no data available (initial state, before the first fetch)

  ## Configuration

      config :sigil_guard,
        registry_enabled: true,
        registry_ttl_ms: 3_600_000,     # 1 hour
        registry_retry_ms: 60_000,      # retry failed fetches after 1 minute
        registry_url: "https://registry.sigil-protocol.org"

  ## Process Model

  The cache is a singleton registered under `#{inspect(__MODULE__)}` —
  one instance per node, supervised by SigilGuard's application when
  `registry_enabled: true` or by the host application otherwise.

  Fetches run synchronously inside the server loop: while a fetch is in
  flight, `patterns/0`, `rule_count/0`, and `source/0` queue for up to
  `:registry_timeout_ms`. Keep that timeout below the callers' own
  `GenServer.call` timeout (5 seconds by default).

  ## Observability

      SigilGuard.Registry.Cache.rule_count()  #=> 42
      SigilGuard.Registry.Cache.source()      #=> :registry

  """

  use GenServer

  alias SigilGuard.Config
  alias SigilGuard.Patterns
  alias SigilGuard.Registry

  require Logger

  @typedoc "Where the current cached data originated."
  @type source :: :registry | :fallback | :empty

  @typedoc "Internal GenServer state."
  @type state :: %{
          patterns: [Patterns.compiled_pattern()],
          raw_bundle: map() | nil,
          source: source(),
          fetched_at: integer() | nil,
          ttl_ms: non_neg_integer(),
          retry_ms: non_neg_integer()
        }

  # -- Client API --

  @doc "Start the registry cache GenServer."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get the current compiled patterns from the cache.

  Falls back to built-in patterns if the cache is empty.
  """
  @spec patterns() :: [Patterns.compiled_pattern()]
  def patterns do
    GenServer.call(__MODULE__, :patterns)
  end

  @doc "Return the number of patterns currently cached."
  @spec rule_count() :: non_neg_integer()
  def rule_count do
    GenServer.call(__MODULE__, :rule_count)
  end

  @doc "Return the source of the current cached data."
  @spec source() :: source()
  def source do
    GenServer.call(__MODULE__, :source)
  end

  @doc "Force a refresh of the cached patterns from the registry."
  @spec refresh() :: :ok
  def refresh do
    GenServer.cast(__MODULE__, :refresh)
  end

  # -- Server Callbacks --

  @impl GenServer
  def init(opts) do
    state = %{
      patterns: [],
      raw_bundle: nil,
      source: :empty,
      fetched_at: nil,
      ttl_ms: Keyword.get(opts, :ttl_ms, Config.registry_ttl_ms()),
      retry_ms: Keyword.get(opts, :retry_ms, Config.registry_retry_ms())
    }

    # Fetch on startup (async to not block supervisor)
    send(self(), :fetch)

    {:ok, state}
  end

  @impl GenServer
  def handle_call(:patterns, _, state) do
    result =
      if state.source == :empty do
        Patterns.built_in()
      else
        state.patterns
      end

    {:reply, result, state}
  end

  def handle_call(:rule_count, _, state) do
    {:reply, length(state.patterns), state}
  end

  def handle_call(:source, _, state) do
    {:reply, state.source, state}
  end

  @impl GenServer
  def handle_cast(:refresh, state) do
    {:noreply, do_fetch(state)}
  end

  @impl GenServer
  def handle_info(:fetch, state) do
    new_state = do_fetch(state)
    schedule_refresh(refresh_interval(new_state))
    {:noreply, new_state}
  end

  # -- Private --

  defp do_fetch(state) do
    case Registry.fetch_bundle() do
      {:ok, bundle} ->
        case Patterns.parse_bundle(bundle) do
          {:ok, raw_patterns} ->
            compiled = Patterns.compile(raw_patterns)
            merged = Patterns.merge(Patterns.built_in(), compiled)
            reg_count = length(compiled)
            total_count = length(merged)

            msg =
              "[SigilGuard.Registry.Cache] Fetched #{reg_count} registry patterns, #{total_count} total after merge"

            Logger.info(msg)

            %{
              state
              | patterns: merged,
                raw_bundle: bundle,
                source: :registry,
                fetched_at: System.monotonic_time(:millisecond)
            }

          {:error, reason} ->
            Logger.warning(
              "[SigilGuard.Registry.Cache] Invalid bundle format: #{inspect(reason)}"
            )

            fallback(state)
        end

      {:error, reason} ->
        Logger.warning("[SigilGuard.Registry.Cache] Fetch failed: #{inspect(reason)}")
        fallback(state)
    end
  end

  defp fallback(%{source: :empty} = state) do
    # No previous data — use built-in patterns
    %{state | patterns: Patterns.built_in(), source: :fallback}
  end

  defp fallback(state) do
    # Keep existing patterns, mark as fallback
    %{state | source: :fallback}
  end

  # Refresh after the TTL on success; retry sooner on failure so the
  # cache does not serve stale data for a full TTL after one bad fetch.
  defp refresh_interval(%{source: :registry, ttl_ms: ttl_ms}), do: ttl_ms
  defp refresh_interval(%{ttl_ms: ttl_ms, retry_ms: retry_ms}), do: min(retry_ms, ttl_ms)

  defp schedule_refresh(interval_ms) do
    Process.send_after(self(), :fetch, interval_ms)
  end
end
