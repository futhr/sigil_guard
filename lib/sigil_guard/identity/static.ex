defmodule SigilGuard.Identity.Static do
  @moduledoc """
  Config-driven actor-to-trust mapping for simple host deployments.

  Hosts repeatedly hand-roll actor-to-trust maps; this implements the
  `SigilGuard.Identity` behaviour over the `:trust_mappings` config so a simple
  prefix table needs no custom module. It is a convenience, not a new seam - a
  host `SigilGuard.Identity` implementation remains the full-power extension
  point, and a richer mapping DSL is parked post-1.0.0.

  `:trust_mappings` is an ordered list of `{pattern, trust_level}` pairs
  evaluated first-match-wins. A pattern is an exact string or a single trailing
  `*` (prefix match); the grammar is validated at boot by
  `SigilGuard.Config.validate!/0`. An actor matching no entry (or an empty
  table) is `:low`. Matching is pure string comparison and never creates atoms.

      config :sigil_guard,
        trust_mappings: [
          {"spiffe://prod/*", :high},
          {"user:*", :medium}
        ]
  """

  @behaviour SigilGuard.Identity

  alias SigilGuard.Config

  @doc "Return the actor string unchanged; non-binary actors map to `\"\"`."
  @impl SigilGuard.Identity
  @spec identity(term()) :: String.t()
  def identity(actor) when is_binary(actor), do: actor
  def identity(_), do: ""

  @doc """
  Return the trust level of the first `:trust_mappings` entry whose pattern
  matches `actor`, or `:low` when none match or the actor is not a string.
  """
  @impl SigilGuard.Identity
  @spec trust_level(term()) :: SigilGuard.Identity.trust_level()
  def trust_level(actor) when is_binary(actor), do: resolve(actor, Config.trust_mappings())
  def trust_level(_), do: :low

  @doc "Static identities carry no additional bindings."
  @impl SigilGuard.Identity
  @spec bindings(term()) :: [String.t()]
  def bindings(_), do: []

  defp resolve(actor, mappings) do
    Enum.find_value(mappings, :low, fn
      {pattern, trust_level} -> if matches?(pattern, actor), do: trust_level
      _ -> nil
    end)
  end

  defp matches?(pattern, actor) when is_binary(pattern) do
    if String.ends_with?(pattern, "*") do
      String.starts_with?(actor, binary_part(pattern, 0, byte_size(pattern) - 1))
    else
      actor == pattern
    end
  end

  defp matches?(_, _), do: false
end
