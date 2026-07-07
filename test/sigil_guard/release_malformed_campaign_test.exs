defmodule SigilGuard.ReleaseMalformedCampaignTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Attestation
  alias SigilGuard.Attestation.AgentPredicate
  alias SigilGuard.Attestation.Digest
  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Attestation.Statement
  alias SigilGuard.BoundaryPolicy
  alias SigilGuard.BoundaryPolicy.File, as: PolicyFile
  alias SigilGuard.CapabilityManifest
  alias SigilGuard.RepoPolicy
  alias SigilGuard.TrustBundle

  @campaign_seeds [
    {10_001, 20_002, 30_003},
    {40_004, 50_005, 60_006},
    {70_007, 80_008, 90_009}
  ]

  @fixed_terms [
    nil,
    true,
    false,
    :unexpected,
    "",
    "not-json",
    <<255, 254, 253>>,
    [],
    [nil, :bad, %{"nested" => <<255>>}],
    %{},
    %{"payload" => "bad"},
    %{"payload" => %{}},
    %{"signatures" => []},
    %{"predicate" => %{"statement_type" => "unknown"}},
    %{"manifest_format" => 123},
    %{"version" => "3", "rules" => [%{"effect" => "execute"}]},
    %{atom: :key, nested: %{bad: <<255>>}}
  ]

  test "public decode and verify entry points classify malformed inputs" do
    for term <- malformed_terms() do
      assert_classified(fn -> Digest.normalize(term) end)
      assert_classified(fn -> Digest.payload_digest(term) end)
      assert_classified(fn -> Digest.context_digest(:unknown_statement_type, term) end)
      assert_classified(fn -> Digest.action_digest(:unknown_statement_type, term, %{}) end)
      assert_classified(fn -> Statement.parse(term) end)
      assert_classified(fn -> Envelope.verify(term, %{}) end)
      assert_classified(fn -> Attestation.verify(term, %{}) end)
      assert_classified(fn -> AgentPredicate.validate(:agent_request, term) end)
      assert_classified(fn -> AgentPredicate.validate(:agent_response, term) end)
      assert_classified(fn -> TrustBundle.verify(term) end)
      assert_classified(fn -> TrustBundle.load(term) end)
      assert_classified(fn -> CapabilityManifest.verify(term, term) end)
      assert_classified(fn -> PolicyFile.parse(term) end)
      assert_classified(fn -> RepoPolicy.compile(term) end)
      assert_classified(fn -> BoundaryPolicy.evaluate(term) end)
    end
  end

  test "text policy parsers classify malformed byte campaigns" do
    for bytes <- malformed_binary_terms() do
      assert_classified(fn -> PolicyFile.parse(bytes) end)
      assert_classified(fn -> RepoPolicy.parse(bytes) end)
    end
  end

  defp assert_classified(fun) do
    case fun.() do
      {:error, reason} -> assert_taxonomy(reason)
      {:ok, _} -> :ok
      :ok -> :ok
      %SigilGuard.Decision{} -> :ok
      other -> flunk("expected classified result, got: #{inspect(other)}")
    end
  rescue
    exception ->
      flunk("malformed input raised #{inspect(exception)}")
  catch
    kind, reason ->
      flunk("malformed input threw #{inspect({kind, reason})}")
  end

  defp assert_taxonomy(reason) when is_atom(reason), do: :ok
  defp assert_taxonomy({reason, _}) when is_atom(reason), do: :ok

  defp assert_taxonomy(reason) do
    flunk("expected taxonomy atom, got: #{inspect(reason)}")
  end

  defp malformed_terms do
    @fixed_terms ++ Enum.flat_map(@campaign_seeds, &random_terms/1)
  end

  defp malformed_binary_terms do
    malformed_terms()
    |> Enum.filter(&is_binary/1)
    |> Kernel.++(["version 3\n[rules]\nallow phase:\n", "[defaults]\naction = nope\n"])
  end

  defp random_terms(seed) do
    :rand.seed(:exsss, seed)
    Enum.map(1..40, fn _ -> random_term(3) end)
  end

  defp random_term(0), do: random_scalar()

  defp random_term(depth) do
    case :rand.uniform(5) do
      1 ->
        random_scalar()

      2 ->
        Enum.map(1..:rand.uniform(3), fn _ -> random_term(depth - 1) end)

      3 ->
        random_string_key_map(depth)

      4 ->
        random_atom_key_map(depth)

      5 ->
        :erlang.list_to_binary(Enum.map(1..:rand.uniform(6), fn _ -> :rand.uniform(256) - 1 end))
    end
  end

  defp random_scalar do
    case :rand.uniform(8) do
      1 -> nil
      2 -> true
      3 -> false
      4 -> :unexpected
      5 -> :rand.uniform(1_000_000)
      6 -> -:rand.uniform(1_000_000)
      7 -> "value-#{:rand.uniform(100)}"
      8 -> :erlang.list_to_binary([255, :rand.uniform(256) - 1])
    end
  end

  defp random_string_key_map(depth) do
    Map.new(1..:rand.uniform(3), fn index ->
      {"key_#{index}_#{:rand.uniform(100)}", random_term(depth - 1)}
    end)
  end

  defp random_atom_key_map(depth) do
    keys = [:actor, :action, :payload]

    Map.new(1..:rand.uniform(3), fn index ->
      {Enum.at(keys, index - 1), random_term(depth - 1)}
    end)
  end
end
