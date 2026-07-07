defmodule SigilGuard.BoundaryPolicyFixture do
  @moduledoc false

  alias SigilGuard.BoundaryPolicy.File, as: PolicyFile
  alias SigilGuard.Canonical.JCS

  @root Path.expand("../fixtures/boundary_policy", __DIR__)

  @doc false
  @spec canonical_path() :: Path.t()
  def canonical_path, do: Path.join(@root, "canonical.policy")

  @doc false
  @spec expected_path() :: Path.t()
  def expected_path, do: Path.join(@root, "canonical.expected.json")

  @doc false
  @spec expected_json() :: binary()
  def expected_json do
    bytes = File.read!(canonical_path())
    {:ok, compiled} = PolicyFile.parse(bytes)
    {:ok, json} = JCS.encode(serialize(compiled))
    json
  end

  @doc false
  @spec write!() :: :ok
  def write! do
    File.write!(expected_path(), expected_json())
  end

  defp serialize(compiled) do
    %{
      "policy_file_digest" => compiled.digest,
      "default" => atom_to_string(compiled.default),
      "rules" => Enum.map(compiled.rules, &serialize_rule/1),
      "contracts" => serialize_contracts(compiled.contracts),
      "repo" => serialize_repo(compiled.repo)
    }
  end

  defp serialize_contracts(contracts) do
    Map.new(contracts, fn {sink, contract} -> {sink, serialize_contract(contract)} end)
  end

  defp serialize_contract(contract) do
    %{
      "max_size" => contract.max_size,
      "no_raw_credentials" => contract.no_raw_credentials,
      "digest_only_pii" => contract.digest_only_pii,
      "classes" => contract.classes && Enum.map(contract.classes, &Atom.to_string/1),
      "credential_transform" => Atom.to_string(contract.credential_transform)
    }
  end

  defp serialize_rule(rule) do
    %{
      "id" => rule.id,
      "decision" => Atom.to_string(rule.decision),
      "matchers" => rule.matchers
    }
  end

  defp serialize_repo(nil), do: nil

  defp serialize_repo(repo) do
    %{
      "default" => Atom.to_string(repo.default),
      "rules" =>
        Enum.map(repo.rules, fn rule ->
          %{
            "id" => rule.id,
            "decision" => Atom.to_string(rule.decision),
            "agents" => rule.agents,
            "actions" => rule.actions,
            "paths" => rule.paths
          }
        end)
    }
  end

  defp atom_to_string(nil), do: nil
  defp atom_to_string(atom), do: Atom.to_string(atom)
end
