defmodule SigilGuard.Identity do
  @moduledoc """
  Identity provider behaviour and trust levels for the SIGIL protocol.

  Trust levels form a monotonic hierarchy — higher levels subsume lower ones.
  The SIGIL protocol uses trust levels to gate access to risky operations:
  a tool classified as `:high` risk requires at least `:verified` trust.

  ## Trust Level Hierarchy

      :anonymous < :authenticated < :verified < :sovereign

  - **anonymous** — No identity assertion. Rate-limited, scan-only access.
  - **authenticated** — Identity proven via token/session. Standard access.
  - **verified** — Identity cryptographically bound (e.g., DID + Ed25519). Elevated access.
  - **sovereign** — Self-sovereign identity with full audit trail. Maximum access.

  ## Implementing an Identity Provider

      defmodule MyApp.SessionIdentity do
        @behaviour SigilGuard.Identity

        @impl true
        def identity(context) do
          "did:web:" <> context.user_id
        end

        @impl true
        def trust_level(context) do
          if context.verified?, do: :verified, else: :authenticated
        end

        @impl true
        def bindings(context) do
          ["session:" <> context.session_id]
        end
      end

  """

  @type trust_level :: :anonymous | :authenticated | :verified | :sovereign

  @doc "Return the identity string (e.g., DID, principal ID) for the given context."
  @callback identity(context :: term()) :: String.t()

  @doc "Return the trust level for the given context."
  @callback trust_level(context :: term()) :: trust_level()

  @doc "Return a list of binding identifiers (session, device, etc.) for the given context."
  @callback bindings(context :: term()) :: [String.t()]

  @trust_order %{
    anonymous: 0,
    authenticated: 1,
    verified: 2,
    sovereign: 3
  }

  @doc """
  Compare two trust levels.

  Returns `:lt`, `:eq`, or `:gt` following the trust hierarchy.

  ## Examples

      iex> SigilGuard.Identity.compare_trust(:anonymous, :verified)
      :lt

      iex> SigilGuard.Identity.compare_trust(:sovereign, :authenticated)
      :gt

      iex> SigilGuard.Identity.compare_trust(:verified, :verified)
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

      iex> SigilGuard.Identity.sufficient_trust?(:verified, :authenticated)
      true

      iex> SigilGuard.Identity.sufficient_trust?(:anonymous, :verified)
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
      [:anonymous, :authenticated, :verified, :sovereign]

  """
  @spec trust_levels() :: [trust_level(), ...]
  def trust_levels do
    [:anonymous, :authenticated, :verified, :sovereign]
  end
end
