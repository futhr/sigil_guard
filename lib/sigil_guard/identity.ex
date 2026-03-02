defmodule SigilGuard.Identity do
  @moduledoc """
  Identity provider behaviour and trust levels for the SIGIL protocol.

  Trust levels form a monotonic hierarchy — higher levels subsume lower ones.
  Matches the `sigil-protocol` Rust crate's `TrustLevel` enum (v0.1.5).

  ## Trust Level Hierarchy

      :low < :medium < :high

  - **low** — Anonymous or unverified user. Rate-limited, scan-only access.
  - **medium** — Verified identity (email, OIDC, social login). Standard access.
  - **high** — Strong verification (eIDAS, government ID, hardware key). Full access.

  ## Implementing an Identity Provider

      defmodule MyApp.SessionIdentity do
        @behaviour SigilGuard.Identity

        @impl true
        def identity(context) do
          "did:web:" <> context.user_id
        end

        @impl true
        def trust_level(context) do
          if context.verified?, do: :high, else: :medium
        end

        @impl true
        def bindings(context) do
          ["session:" <> context.session_id]
        end
      end

  """

  @type trust_level :: :low | :medium | :high

  @doc "Return the identity string (e.g., DID, principal ID) for the given context."
  @callback identity(context :: term()) :: String.t()

  @doc "Return the trust level for the given context."
  @callback trust_level(context :: term()) :: trust_level()

  @doc "Return a list of binding identifiers (session, device, etc.) for the given context."
  @callback bindings(context :: term()) :: [String.t()]

  @trust_order %{
    low: 0,
    medium: 1,
    high: 2
  }

  @doc """
  Compare two trust levels.

  Returns `:lt`, `:eq`, or `:gt` following the trust hierarchy.

  ## Examples

      iex> SigilGuard.Identity.compare_trust(:low, :high)
      :lt

      iex> SigilGuard.Identity.compare_trust(:high, :medium)
      :gt

      iex> SigilGuard.Identity.compare_trust(:medium, :medium)
      :eq

  """
  @spec compare_trust(trust_level(), trust_level()) :: :lt | :eq | :gt
  def compare_trust(a, b) do
    ord_a = Map.fetch!(@trust_order, a)
    ord_b = Map.fetch!(@trust_order, b)

    cond do
      ord_a < ord_b -> :lt
      ord_a > ord_b -> :gt
      true -> :eq
    end
  end

  @doc """
  Check if `actual` trust level meets or exceeds the `required` trust level.

  ## Examples

      iex> SigilGuard.Identity.sufficient_trust?(:high, :medium)
      true

      iex> SigilGuard.Identity.sufficient_trust?(:low, :high)
      false

  """
  @spec sufficient_trust?(trust_level(), trust_level()) :: boolean()
  def sufficient_trust?(actual, required) do
    compare_trust(actual, required) in [:eq, :gt]
  end

  @doc """
  Return all trust levels in ascending order.

  ## Examples

      iex> SigilGuard.Identity.trust_levels()
      [:low, :medium, :high]

  """
  @spec trust_levels() :: [trust_level(), ...]
  def trust_levels do
    [:low, :medium, :high]
  end
end
